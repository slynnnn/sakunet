package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakunet/internal/surge"
)

const profileConfA = `[Proxy]
NodeA = snell, 192.0.2.1, 8000, psk=secret, version=5

[Proxy Group]
Main = select, NodeA, DIRECT

[Rule]
FINAL,Main
`

const profileConfB = `[Proxy]
NodeB = trojan, 192.0.2.2, 443, password=secret

[Proxy Group]
Main = select, NodeB, DIRECT

[Rule]
FINAL,Main
`

func newProfileManager(t *testing.T, dir string) *Manager {
	t.Helper()
	return &Manager{appDir: dir, nodesPath: filepath.Join(dir, "nodes.json"), mode: "rule", sourceKind: "nodes"}
}

func TestProfilesLifecycle(t *testing.T) {
	dir := t.TempDir()
	m := newProfileManager(t, dir)
	if _, err := m.ImportSurge("a.conf", []byte(profileConfA), "档案甲"); err != nil {
		t.Fatalf("import A: %v", err)
	}
	if _, err := m.ImportSurge("b.conf", []byte(profileConfB), "档案乙"); err != nil {
		t.Fatalf("import B: %v", err)
	}
	list, err := m.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("profiles = %d, want 2", len(list))
	}
	var aID, bID string
	for _, p := range list {
		switch p.Name {
		case "档案甲":
			aID = p.ID
		case "档案乙":
			bID = p.ID
			if !p.Active {
				t.Error("latest import (乙) should be active")
			}
		}
	}
	// Active model is B right now.
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil || len(imp.Nodes) != 1 || imp.Nodes[0].Name != "NodeB" {
		t.Fatalf("active model after imports = %+v, %v", imp, err)
	}
	// Switch back to A.
	if err := m.SwitchProfile(aID); err != nil {
		t.Fatalf("switch: %v", err)
	}
	imp, err = surge.LoadImported(m.importedPath())
	if err != nil || len(imp.Nodes) != 1 || imp.Nodes[0].Name != "NodeA" {
		t.Fatalf("active model after switch = %+v, %v", imp, err)
	}
	// Deleting the active profile is refused; deleting B works.
	if err := m.DeleteProfile(aID); err == nil {
		t.Error("deleting the active profile must be refused")
	}
	if err := m.DeleteProfile(bID); err != nil {
		t.Fatalf("delete B: %v", err)
	}
	list, _ = m.Profiles()
	if len(list) != 1 || list[0].Name != "档案甲" {
		t.Errorf("profiles after delete = %+v", list)
	}
	if _, err := os.Stat(m.profilePath(bID)); !os.IsNotExist(err) {
		t.Error("deleted profile file still exists")
	}
	if err := m.SwitchProfile("no-such-id"); err == nil {
		t.Error("switching to a missing profile must fail")
	}
}

func TestProfileMigrationFromSingleFile(t *testing.T) {
	dir := t.TempDir()
	m := newProfileManager(t, dir)
	// Simulate a pre-v1.2 install: imported.json + source meta,
	// no profiles directory.
	imp, err := surge.Parse("old.conf", []byte(profileConfA))
	if err != nil {
		t.Fatal(err)
	}
	if err := surge.SaveImported(imp, m.importedPath()); err != nil {
		t.Fatal(err)
	}
	m.sourceKind = "surge"
	m.ensureProfiles()
	list, err := m.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "默认档案" || !list[0].Active {
		t.Fatalf("migrated profiles = %+v", list)
	}
	// Migration is idempotent.
	m.ensureProfiles()
	list, _ = m.Profiles()
	if len(list) != 1 {
		t.Errorf("second ensureProfiles duplicated: %+v", list)
	}
	if !strings.Contains(list[0].Source, "old.conf") && list[0].Source != "" {
		t.Errorf("source name = %q", list[0].Source)
	}
}
