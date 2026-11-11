package mitm

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakunet/internal/script"
	"sakunet/internal/surge"
)

// End-to-end for the v1.1 JS engine inside the MITM layer: a real
// curl request over a CONNECT+TLS interception where (1) a
// http-request script injects a header the origin echoes back,
// (2) a http-response script strips an ad field from the JSON
// body, and (3) a second path is rejected outright by a request
// script's $done({response:{...}}).
func TestScriptEngineEndToEnd(t *testing.T) {
	mitmCA, mitmKey, mitmCAPEM := makeCA(t, "SakuNet Script Test CA")
	originCA, originKey, _ := makeCA(t, "Script Origin CA")
	dir := t.TempDir()
	mitmCAPath := filepath.Join(dir, "mitm-ca.pem")
	if err := os.WriteFile(mitmCAPath, mitmCAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ad":"BUY-NOW","items":[1,2],"via":%q}`, r.Header.Get("X-From-Script"))
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin-should-never-see-this")
	})
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		fmt.Fprint(zw, `{"ad":"GZ-AD","keep":1}`)
		_ = zw.Close()
	})
	leaf := makeLeaf(t, originCA, originKey, "test.local", 21)
	s := httptest.NewUnstartedServer(mux)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	s.StartTLS()
	defer s.Close()
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	var oport int
	fmt.Sscanf(p, "%d", &oport)

	mkDef := func(name, typ, pattern, code string) surge.ScriptDef {
		return surge.ScriptDef{
			Name:   name,
			Params: map[string]string{"type": typ, "pattern": pattern},
			Resolved: &surge.ResolvedScript{
				Type: typ, Pattern: pattern, Code: code, Enabled: true,
				TimeoutSec: 5, Source: "https://scripts.example/" + name + ".js",
			},
		}
	}
	ed2 := &surge.EngineData{Scripts: []surge.ScriptDef{
		mkDef("inject", "http-request", `/feed`,
			`$request.headers["x-from-script"] = "script-7"; $done({ headers: $request.headers });`),
		mkDef("strip-ad", "http-response", `/feed`,
			`var o = JSON.parse($response.body); delete o.ad; $done({ body: JSON.stringify(o) });`),
		mkDef("block", "http-request", `/blocked`,
			`$done({ response: { status: 403, body: "no-ads-here" } });`),
		mkDef("strip-gz", "http-response", `/gz`,
			`var o = JSON.parse($response.body); delete o.ad; $done({ body: JSON.stringify(o) });`),
	}}
	runner := script.NewRunner(script.FromEngine(ed2), script.Options{StorePath: filepath.Join(dir, "store.json")})

	roots := x509.NewCertPool()
	roots.AddCert(originCA)
	srv, err := Start(Config{
		Hostnames:     []string{"test.local"},
		Engine:        (&surge.EngineData{}).Compile(),
		Scripts:       runner,
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

	// (1)+(2): header injected by the request script is visible in
	// the origin's echo; the ad field is gone from the final body.
	out, serr := curl(t, "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", resolve, fmt.Sprintf("https://test.local:%d/feed", oport))
	if strings.Contains(out, "BUY-NOW") || strings.Contains(out, `"ad"`) {
		t.Errorf("ad field survived the response script, got:\n%s\nstderr:\n%s", out, serr)
	}
	if !strings.Contains(out, `"via":"script-7"`) {
		t.Errorf("request script header not seen by origin, got:\n%s\nstderr:\n%s", out, serr)
	}
	if !strings.Contains(out, `"items":[1,2]`) {
		t.Errorf("legit body content lost, got:\n%s", out)
	}
	t.Logf("scripted body: %s", strings.TrimSpace(out))

	// (3): request script short-circuits with its own response.
	out, _ = curl(t, "-i", "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", resolve, fmt.Sprintf("https://test.local:%d/blocked", oport))
	if !strings.Contains(out, "403") || !strings.Contains(out, "no-ads-here") {
		t.Errorf("script reject failed, got:\n%s", out)
	}
	if strings.Contains(out, "origin-should-never-see-this") {
		t.Errorf("rejected request reached the origin:\n%s", out)
	}
	t.Logf("reject response head:\n%s", firstLines(out, 4))

	// (4): gzip-encoded JSON — the script sees the decoded body,
	// its rewrite goes back out as plain JSON (no gzip framing).
	out, _ = curl(t, "-x", proxy, "--cacert", mitmCAPath,
		"--resolve", resolve, fmt.Sprintf("https://test.local:%d/gz", oport))
	if strings.Contains(out, "GZ-AD") || !strings.Contains(out, `"keep":1`) {
		t.Errorf("gzip scripted body wrong, got:\n%q", out)
	}
	t.Logf("gzip scripted body: %s", strings.TrimSpace(out))

	// Engine log shows all scripts ran clean.
	infos := runner.Infos()
	for _, in := range infos {
		if !in.LastOK {
			t.Errorf("script %s not ok: %+v", in.Name, in)
		}
	}
}
