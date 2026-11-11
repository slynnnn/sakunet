//go:build !windows

package core

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubscriptionAutoUpdate(t *testing.T) {
	dir := t.TempDir()
	fakeCore(t, dir)
	sub := "trojan://pw@192.0.2.5:443#SubNode\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(sub)))
	}))
	defer srv.Close()

	m := &Manager{appDir: dir, nodesPath: filepath.Join(dir, "nodes.json"), mode: "rule", sourceKind: "nodes"}
	if err := m.SetSubscription(srv.URL, 12, true); err != nil {
		t.Fatalf("SetSubscription: %v", err)
	}
	if err := m.SetSubscription("ftp://x", 12, true); err == nil {
		t.Error("non-http subscription URL must be rejected")
	}
	if err := m.runSubscriptionUpdate(); err != nil {
		t.Fatalf("runSubscriptionUpdate: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "SubNode") {
		t.Errorf("nodes.json did not gain the subscription node:\n%s", raw)
	}
	v := m.Automation()
	if !v.SubAuto || v.SubEveryH != 12 || v.SubLastAt == "" || !strings.Contains(v.SubLastMsg, "新增 1") {
		t.Errorf("automation view = %+v", v)
	}
	// Idempotent: a second run adds nothing new.
	if err := m.runSubscriptionUpdate(); err != nil {
		t.Fatal(err)
	}
	if v := m.Automation(); !strings.Contains(v.SubLastMsg, "新增 0") {
		t.Errorf("second run msg = %q", v.SubLastMsg)
	}
	// Prefs survive a reload.
	m2 := &Manager{appDir: dir, nodesPath: filepath.Join(dir, "nodes.json"), mode: "rule", sourceKind: "nodes"}
	m2.loadPrefs()
	if m2.prefs.SubURL != srv.URL || !m2.prefs.SubAuto {
		t.Errorf("prefs did not round-trip: %+v", m2.prefs)
	}
	// Not due yet: maybeUpdateSubscription must be a no-op (the
	// server is closed after this, a fetch would fail loudly).
	m.maybeUpdateSubscription()
	if v := m.Automation(); !strings.Contains(v.SubLastMsg, "新增 0") {
		t.Errorf("maybeUpdate ran while not due: %q", v.SubLastMsg)
	}
}

func TestSetAutostartUnsupportedPlatform(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{appDir: dir, nodesPath: filepath.Join(dir, "nodes.json"), mode: "rule", sourceKind: "nodes"}
	if err := m.SetAutostart(true); err == nil {
		t.Error("autostart on a non-Windows build must error, not fake success")
	}
	if m.Automation().AutostartSupported {
		t.Error("stub must report unsupported")
	}
}
