package mitm

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sakunet/internal/surge"
)

func makeCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}

func makeLeaf(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, dns string, serial int64) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// startStubProxy is a minimal CONNECT proxy that maps any
// host:port target to 127.0.0.1:port. Fake hostnames like
// test.local do not resolve on a test machine, so the MITM proxy
// under test chains through this stub — the same code path as
// production, where it chains through sing-box's mixed inbound.
func startStubProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				_, port, err := net.SplitHostPort(req.Host)
				if err != nil {
					return
				}
				up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				go func() { _, _ = io.Copy(up, br); up.Close() }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startOrigin(t *testing.T, cert tls.Certificate) (port int, srv *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin path=%s x-mitm-test=%s", r.URL.Path, r.Header.Get("X-Mitm-Test"))
	})
	s := httptest.NewUnstartedServer(mux)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	fmt.Sscanf(p, "%d", &port)
	return port, s
}

func curl(t *testing.T, args ...string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	full := append([]string{"-sS", "--max-time", "15", "-N"}, args...)
	cmd := exec.Command("curl", full...)
	cmd.Env = append(os.Environ(), "no_proxy=", "NO_PROXY=")
	var out, serr strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &serr
	_ = cmd.Run() // curl exits non-zero for some expected cases (e.g. 302 without -L is fine=0)
	return out.String(), serr.String()
}

// End-to-end: real curl through the MITM proxy against a local
// self-signed HTTPS origin. Verifies (1) 302 rewrite + Location,
// (2) a request-header rewrite visible at the origin, (3) a
// non-MITM host is tunneled byte-for-byte: curl validates the
// ORIGIN's certificate (issued by a different CA than the MITM CA),
// which would fail if the proxy had decrypted the connection.
func TestMITMEndToEnd(t *testing.T) {
	mitmCA, mitmKey, mitmCAPEM := makeCA(t, "SakuNet Test MITM CA")
	originCA, originKey, originCAPEM := makeCA(t, "Test Origin CA")
	dir := t.TempDir()
	mitmCAPath := filepath.Join(dir, "mitm-ca.pem")
	originCAPath := filepath.Join(dir, "origin-ca.pem")
	if err := os.WriteFile(mitmCAPath, mitmCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(originCAPath, originCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	op1, o1 := startOrigin(t, makeLeaf(t, originCA, originKey, "test.local", 11))
	defer o1.Close()
	op2, o2 := startOrigin(t, makeLeaf(t, originCA, originKey, "other.local", 12))
	defer o2.Close()

	ed := &surge.EngineData{URLRewrites: []surge.RewriteRule{
		{Raw: `^https://test\.local/old https://test.local/new 302`},
		{Raw: `^https://test\.local/echo header-set X-Mitm-Test injected-42`},
	}}
	ce := ed.Compile()
	if len(ce.Rules) != 2 || len(ce.Unsupported) != 0 {
		t.Fatalf("compile: rules=%d unsupported=%v", len(ce.Rules), ce.Unsupported)
	}
	roots := x509.NewCertPool()
	roots.AddCert(originCA)
	srv, err := Start(Config{
		Hostnames:     []string{"test.local"},
		Engine:        ce,
		CA:            tls.Certificate{Certificate: [][]byte{mitmCA.Raw}, PrivateKey: mitmKey, Leaf: mitmCA},
		UpstreamProxy: startStubProxy(t),
		UpstreamRoots: roots,
	}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	proxy := "http://" + srv.Addr()

	// (1) 302 rewrite with correct Location.
	out, _ := curl(t, "-i", "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", fmt.Sprintf("test.local:%d:127.0.0.1", op1),
		fmt.Sprintf("https://test.local:%d/old", op1))
	if !strings.Contains(out, "302") || !strings.Contains(out, "Location: https://test.local/new") {
		t.Errorf("(1) redirect failed, got:\n%s", out)
	}
	t.Logf("(1) redirect response head:\n%s", firstLines(out, 6))

	// (2) header rewrite visible at the origin.
	out, _ = curl(t, "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", fmt.Sprintf("test.local:%d:127.0.0.1", op1),
		fmt.Sprintf("https://test.local:%d/echo", op1))
	if !strings.Contains(out, "x-mitm-test=injected-42") {
		t.Errorf("(2) header rewrite not visible at origin, got:\n%s", out)
	}
	t.Logf("(2) origin body: %s", strings.TrimSpace(out))

	// (3) non-MITM host: tunneled, origin cert validates against
	// the ORIGIN CA — proof the proxy did not decrypt.
	out, serr := curl(t, "-v", "-x", proxy, "--cacert", originCAPath,
		"--resolve", fmt.Sprintf("other.local:%d:127.0.0.1", op2),
		fmt.Sprintf("https://other.local:%d/echo", op2))
	if !strings.Contains(out, "origin path=/echo") {
		t.Errorf("(3) tunneled request failed, got:\n%s\nstderr:\n%s", out, serr)
	}
	if _, leafMade := srv.leafs["other.local"]; leafMade {
		t.Errorf("(3) proxy minted a leaf for other.local — it decrypted a non-MITM host")
	}
	t.Logf("(3) tunneled body: %s", strings.TrimSpace(out))
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
