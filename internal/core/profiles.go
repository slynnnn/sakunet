package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sakunet/internal/surge"
)

// Config profiles (v1.2): every Surge import is kept as a named
// profile under appDir/profiles/ instead of overwriting the
// previous import. imported.json remains the materialized active
// profile (the rest of the app reads exactly one active model);
// switching profiles re-materializes it and restarts the core.
//
// The pre-v1.2 single imported.json migrates transparently: on
// first use it becomes the profile "默认档案".

type profileEntry struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	SourceName string    `json:"source_name,omitempty"`
	At         time.Time `json:"at"`
}

type profileIndex struct {
	Profiles []profileEntry `json:"profiles"`
	ActiveID string         `json:"active_id,omitempty"`
}

// ProfileView is one profile row for the settings page.
type ProfileView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source_name,omitempty"`
	At     string `json:"at"`
	Active bool   `json:"active"`
}

func (m *Manager) profilesDir() string  { return filepath.Join(m.appDir, "profiles") }
func (m *Manager) profileIndexPath() string {
	return filepath.Join(m.profilesDir(), "index.json")
}
func (m *Manager) profilePath(id string) string {
	return filepath.Join(m.profilesDir(), id+".json")
}

func (m *Manager) loadProfileIndex() (*profileIndex, error) {
	raw, err := os.ReadFile(m.profileIndexPath())
	if err != nil {
		return &profileIndex{}, nil // no profiles yet is not an error
	}
	var idx profileIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("档案索引损坏：%w", err)
	}
	return &idx, nil
}

func (m *Manager) saveProfileIndex(idx *profileIndex) error {
	if err := os.MkdirAll(m.profilesDir(), 0o755); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(idx, "", "  ")
	return os.WriteFile(m.profileIndexPath(), append(raw, '\n'), 0o600)
}

func newProfileID(name string, at time.Time) string {
	sum := sha256.Sum256([]byte(name + at.String()))
	return at.Format("20060102-150405") + "-" + hex.EncodeToString(sum[:3])
}

// ensureProfiles performs the one-time migration from the
// single-file layout and restores the active profile id. Called
// from New; safe to call repeatedly.
func (m *Manager) ensureProfiles() {
	if m.sourceKind != "surge" {
		return
	}
	idx, err := m.loadProfileIndex()
	if err != nil || len(idx.Profiles) > 0 {
		if idx != nil {
			m.activeProfile = idx.ActiveID
		}
		return
	}
	// Migrate the existing imported.json as the default profile.
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil {
		return
	}
	id := newProfileID("默认档案", imp.ImportedAt)
	if err := os.MkdirAll(m.profilesDir(), 0o755); err != nil {
		return
	}
	if err := surge.SaveImported(imp, m.profilePath(id)); err != nil {
		return
	}
	idx = &profileIndex{
		Profiles: []profileEntry{{ID: id, Name: "默认档案", SourceName: imp.SourceName, At: imp.ImportedAt}},
		ActiveID: id,
	}
	if err := m.saveProfileIndex(idx); err == nil {
		m.activeProfile = id
	}
}

// saveActiveImported persists the active model to imported.json
// and, when profiles are in use, to the active profile file too,
// so node/module merges survive profile switches.
func (m *Manager) saveActiveImported(imp *surge.Imported) error {
	if err := surge.SaveImported(imp, m.importedPath()); err != nil {
		return err
	}
	m.mu.Lock()
	active := m.activeProfile
	m.mu.Unlock()
	if active != "" {
		_ = surge.SaveImported(imp, m.profilePath(active))
	}
	return nil
}

// addProfile stores imp as a new profile and makes it active.
func (m *Manager) addProfile(name string, imp *surge.Imported) (string, error) {
	idx, err := m.loadProfileIndex()
	if err != nil {
		return "", err
	}
	id := newProfileID(name, imp.ImportedAt)
	if err := os.MkdirAll(m.profilesDir(), 0o755); err != nil {
		return "", err
	}
	if err := surge.SaveImported(imp, m.profilePath(id)); err != nil {
		return "", err
	}
	idx.Profiles = append(idx.Profiles, profileEntry{
		ID: id, Name: name, SourceName: imp.SourceName, At: imp.ImportedAt,
	})
	idx.ActiveID = id
	if err := m.saveProfileIndex(idx); err != nil {
		return "", err
	}
	m.mu.Lock()
	m.activeProfile = id
	m.mu.Unlock()
	return id, nil
}

// Profiles lists all profiles with the active one marked.
func (m *Manager) Profiles() ([]ProfileView, error) {
	idx, err := m.loadProfileIndex()
	if err != nil {
		return nil, err
	}
	out := []ProfileView{}
	for _, p := range idx.Profiles {
		out = append(out, ProfileView{
			ID: p.ID, Name: p.Name, Source: p.SourceName,
			At: p.At.Format("2006-01-02 15:04"), Active: p.ID == idx.ActiveID,
		})
	}
	return out, nil
}

// SwitchProfile makes another profile the active configuration.
func (m *Manager) SwitchProfile(id string) error {
	idx, err := m.loadProfileIndex()
	if err != nil {
		return err
	}
	var entry *profileEntry
	for i := range idx.Profiles {
		if idx.Profiles[i].ID == id {
			entry = &idx.Profiles[i]
		}
	}
	if entry == nil {
		return fmt.Errorf("档案不存在")
	}
	if idx.ActiveID == id {
		return nil
	}
	imp, err := surge.LoadImported(m.profilePath(id))
	if err != nil {
		return fmt.Errorf("档案读取失败：%w", err)
	}
	if err := surge.SaveImported(imp, m.importedPath()); err != nil {
		return err
	}
	idx.ActiveID = id
	if err := m.saveProfileIndex(idx); err != nil {
		return err
	}
	m.mu.Lock()
	m.activeProfile = id
	m.sourceKind = "surge"
	m.sourceName = imp.SourceName
	m.sourceAt = imp.ImportedAt
	running := m.cmd != nil
	m.mu.Unlock()
	meta := sourceMeta{Kind: "surge", SourceName: imp.SourceName, At: imp.ImportedAt, ProfileID: id}
	if raw, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(m.sourceMetaPath(), raw, 0o644)
	}
	if running {
		if err := m.Restart(); err != nil {
			return fmt.Errorf("档案已切换，但内核重启失败：%w", err)
		}
	}
	return nil
}

// DeleteProfile removes a non-active profile.
func (m *Manager) DeleteProfile(id string) error {
	idx, err := m.loadProfileIndex()
	if err != nil {
		return err
	}
	if idx.ActiveID == id {
		return fmt.Errorf("不能删除当前生效的档案，请先切换到其他档案")
	}
	kept := idx.Profiles[:0]
	found := false
	for _, p := range idx.Profiles {
		if p.ID == id {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return fmt.Errorf("档案不存在")
	}
	idx.Profiles = kept
	if err := m.saveProfileIndex(idx); err != nil {
		return err
	}
	_ = os.Remove(m.profilePath(id))
	return nil
}
