package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakunet/internal/surge"
)

// End-to-end for the v1.2 native body rewrites inside the MITM
// layer: a response-body rule strips an ad value from the origin's
// JSON, and a request-body rule redacts a token before the origin
// sees it. Both run over a real CONNECT+TLS interception via curl.
func TestBodyRewriteEndToEnd(t *testing.T) {
	mitmCA, mitmKey, mitmCAPEM := makeCA(t, "SakuNet Body Test CA")
	originCA, originKey, _ := makeCA(t, "Body Origin CA")
	dir := t.TempDir()
	mitmCAPath := filepath.Join(dir, "mitm-ca.pem")
	if err := os.WriteFile(mitmCAPath, mitmCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ad":"BUY-NOW","items":[1,2]}`)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "echo:%s", b)
	})
	leaf := makeLeaf(t, originCA, originKey, "test.local", 31)
	s := httptest.NewUnstartedServer(mux)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	s.StartTLS()
	defer s.Close()
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	var oport int
	fmt.Sscanf(p, "%d", &oport)

	ed := &surge.EngineData{URLRewrites: []surge.RewriteRule{
		{Raw: `^https://test\.local(:\d+)?/feed response-body "ad":"[^"]*" "ad":""`},
		{Raw: `^https://test\.local(:\d+)?/echo request-body token=\w+ token=REDACTED`},
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
	resolve := fmt.Sprintf("test.local:%d:127.0.0.1", oport)

	out, serr := curl(t, "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", resolve, fmt.Sprintf("https://test.local:%d/feed", oport))
	if strings.Contains(out, "BUY-NOW") {
		t.Errorf("ad value survived response-body rewrite:\n%s\n%s", out, serr)
	}
	if !strings.Contains(out, `"ad":""`) || !strings.Contains(out, `"items":[1,2]`) {
		t.Errorf("rewritten body wrong:\n%s", out)
	}

	out, _ = curl(t, "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", resolve, "-d", "user=u1&token=abc123xyz",
		fmt.Sprintf("https://test.local:%d/echo", oport))
	if !strings.Contains(out, "echo:user=u1&token=REDACTED") {
		t.Errorf("request-body rewrite wrong:\n%s", out)
	}
	if strings.Contains(out, "abc123xyz") {
		t.Errorf("raw token reached the origin:\n%s", out)
	}
}
