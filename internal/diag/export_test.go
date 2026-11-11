package diag

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakunet/internal/api"
	"sakunet/internal/core"
)

// The bundle built over a store full of FAKE credentials must not
// contain any of them, in any member.
func TestBundleRedaction(t *testing.T) {
	dir := t.TempDir()
	nodes := `{
  "nodes": [
    {"name": "Fake A", "type": "snell", "server": "fake-node-a.example.com", "port": 17886,
     "psk": "FAKE-PSK-9f8e7d6c", "version": 6},
    {"name": "Fake B", "type": "trojan", "server": "203.0.113.99", "port": 443,
     "password": "FAKE-TROJAN-PASS-12345", "sni": "fake-node-a.example.com"}
  ]
}`
	nodesPath := filepath.Join(dir, "nodes.json")
	if err := os.WriteFile(nodesPath, []byte(nodes), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := core.New(nodesPath)
	if err != nil {
		t.Fatal(err)
	}
	fakeSecrets := []string{
		"fake-node-a.example.com", "203.0.113.99",
		"FAKE-PSK-9f8e7d6c", "FAKE-TROJAN-PASS-12345",
	}
	// The redactor's secret list must actually contain the fakes,
	// otherwise this test proves nothing.
	have := strings.Join(mgr.Secrets(), "|")
	for _, s := range fakeSecrets {
		if !strings.Contains(have, s) {
			t.Fatalf("Secrets() missing %q (got %v)", s, mgr.Secrets())
		}
	}
	bundle, _, err := BuildBundle(mgr, api.New("http://127.0.0.1:1"), "v-test")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) == 0 {
		t.Fatal("empty bundle")
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := rc.Read(buf)
			sb.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		rc.Close()
		content := sb.String()
		for _, s := range fakeSecrets {
			if strings.Contains(content, s) {
				t.Errorf("bundle member %s leaks fake secret %q", f.Name, s)
			}
		}
	}
}

func TestRedactPatterns(t *testing.T) {
	blob := strings.Repeat("QUJDREVGRw==", 20) // long base64-shaped run
	text := "connecting password=hunter2 ok\npsk: abc123\nblob " + blob + "\nnormal line stays"
	out := Redact(text, []string{"hunter2"})
	for _, bad := range []string{"hunter2", "abc123", blob} {
		if strings.Contains(out, bad) {
			t.Errorf("Redact leaked %q in %q", bad, out)
		}
	}
	if !strings.Contains(out, "normal line stays") {
		t.Errorf("Redact damaged innocent text: %q", out)
	}
}
