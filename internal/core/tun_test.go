//go:build !windows

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCore installs a shell-script sing-box stand-in in dir. Its
// `check` subcommand fails exactly once when a fail-once marker
// file exists (and consumes the marker), which lets the test force
// the first post-toggle restart to fail and the rollback restart
// to succeed.
func fakeCore(t *testing.T, dir string) {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in
  version) echo "sing-box version 1.14.4 (fake)";;
  check)
    if [ -f %q ]; then rm %q; echo "injected check failure" >&2; exit 1; fi
    exit 0;;
  run) exec sleep 300;;
esac
`, filepath.Join(dir, "fail-once"), filepath.Join(dir, "fail-once"))
	if err := os.WriteFile(filepath.Join(dir, "sing-box"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	nodes := `{"nodes":[{"name":"A","type":"snell","server":"192.0.2.1","port":8000,"psk":"x","version":5}]}`
	if err := os.WriteFile(filepath.Join(dir, "nodes.json"), []byte(nodes), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetTunRollbackOnRestartFailure(t *testing.T) {
	dir := t.TempDir()
	fakeCore(t, dir)
	m := &Manager{appDir: dir, nodesPath: filepath.Join(dir, "nodes.json"), mode: "rule", sourceKind: "nodes"}
	if err := m.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()
	if !m.Status().Running {
		t.Fatal("core should be running")
	}
	// Force the restart after toggling TUN on to fail once.
	if err := os.WriteFile(filepath.Join(dir, "fail-once"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := m.SetTun(true)
	if err == nil {
		t.Fatal("SetTun should report the failed toggle")
	}
	if !strings.Contains(err.Error(), "已回滚") {
		t.Errorf("error should state the rollback, got: %v", err)
	}
	if m.Tun() {
		t.Error("tun preference must be rolled back to false")
	}
	raw, _ := os.ReadFile(m.prefsPath())
	if !strings.Contains(string(raw), `"tun":false`) {
		t.Errorf("prefs file = %s, want tun:false persisted", raw)
	}
	if !m.Status().Running {
		t.Error("core must be running again on the rolled-back config")
	}
	// A clean toggle (no injected failure) applies and persists.
	if err := m.SetTun(true); err != nil {
		t.Fatalf("clean SetTun(true): %v", err)
	}
	if !m.Tun() || !m.Status().Running {
		t.Error("after clean toggle: tun on and core running expected")
	}
	if err := m.SetTun(false); err != nil {
		t.Fatalf("clean SetTun(false): %v", err)
	}
}
