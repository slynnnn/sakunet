// Package core manages the sing-box sidecar process lifecycle.
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"sakunet/internal/config"
	"sakunet/internal/mitm"
	"sakunet/internal/script"
	"sakunet/internal/surge"
)

type Status struct {
	Mode       string    `json:"mode"`
	Running    bool      `json:"running"`
	PID        int       `json:"pid,omitempty"`
	Binary     string    `json:"binary,omitempty"`
	NodesFile  string    `json:"nodes_file,omitempty"`
	Version    string    `json:"version,omitempty"`
	Error      string    `json:"error,omitempty"`
	SourceKind string    `json:"source_kind"` // nodes | surge
	SourceName string    `json:"source_name,omitempty"`
	SourceAt   string    `json:"source_at,omitempty"`
	Configured bool      `json:"configured"` // an imported config or a nodes.json exists
	Tun        bool      `json:"tun"`
	MITM       *MITMInfo `json:"mitm,omitempty"`
}

type Manager struct {
	mu           sync.Mutex
	cmd          *exec.Cmd
	done         chan struct{}
	appDir       string
	nodesPath    string
	binary       string
	version      string
	lastErr      string
	mode         string
	sourceKind   string // "nodes" (hand-written nodes.json) or "surge" (imported)
	sourceName   string
	sourceAt     time.Time
	tun          bool
	mitmSrv      *mitm.Server
	mitmInfo     *MITMInfo
	scriptRunner *script.Runner
}

// sourceMeta is sakunet-source.json: which configuration source is
// active. Absent file = hand-written nodes.json.
type sourceMeta struct {
	Kind       string    `json:"kind"`
	SourceName string    `json:"source_name,omitempty"`
	At         time.Time `json:"at,omitempty"`
}

// New resolves the app directory (executable dir, falling back to cwd)
// and the nodes.json location.
func New(nodesPath string) (*Manager, error) {
	dir, err := os.Executable()
	if err != nil {
		dir, _ = os.Getwd()
	} else {
		dir = filepath.Dir(dir)
	}
	if nodesPath == "" {
		nodesPath = filepath.Join(dir, "nodes.json")
		if _, err := os.Stat(nodesPath); err != nil {
			if cwd, e := os.Getwd(); e == nil {
				if _, err2 := os.Stat(filepath.Join(cwd, "nodes.json")); err2 == nil {
					nodesPath = filepath.Join(cwd, "nodes.json")
					dir = cwd
				}
			}
		}
	} else if abs, err := filepath.Abs(nodesPath); err == nil {
		nodesPath = abs
	}
	m := &Manager{appDir: dir, nodesPath: nodesPath, mode: "rule", sourceKind: "nodes"}
	m.loadPrefs()
	if raw, err := os.ReadFile(m.modePath()); err == nil {
		var v struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(raw, &v) == nil && (v.Mode == "global" || v.Mode == "direct") {
			m.mode = v.Mode
		}
	}
	if raw, err := os.ReadFile(m.sourceMetaPath()); err == nil {
		var meta sourceMeta
		if json.Unmarshal(raw, &meta) == nil && meta.Kind == "surge" {
			if _, err := os.Stat(m.importedPath()); err == nil {
				m.sourceKind = "surge"
				m.sourceName = meta.SourceName
				m.sourceAt = meta.At
			}
		}
	}
	return m, nil
}

func (m *Manager) modePath() string       { return filepath.Join(m.appDir, "sakunet-mode.json") }
func (m *Manager) sourceMetaPath() string { return filepath.Join(m.appDir, "sakunet-source.json") }
func (m *Manager) importedPath() string   { return filepath.Join(m.appDir, "imported.json") }

// generate renders the sing-box config from the active source.
func (m *Manager) generate() error {
	if m.sourceKind == "surge" {
		return surge.GenerateImported(m.importedPath(), m.configPath(), m.mode, m.tun)
	}
	f, err := config.Load(m.nodesPath)
	if err != nil {
		return err
	}
	if m.tun {
		f.Tun = true
	}
	cfg, err := config.Build(f, m.mode)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath(), append(raw, '\n'), 0o644)
}

// ImportSurge parses an uploaded Surge .conf, persists it as the
// active configuration source (imported.json) and restarts the core
// if it is running. The hand-written nodes.json is left untouched;
// switching back is a matter of removing the source meta (settings
// page shows which source is active).
func (m *Manager) ImportSurge(origName string, data []byte) (*surge.Report, error) {
	imp, err := surge.Parse(origName, data)
	if err != nil {
		return nil, err
	}
	if imp.Report.NodesOK == 0 && imp.Report.GroupsOK == 0 {
		return nil, fmt.Errorf("未从 %s 解析出任何节点或策略组，请确认文件是 Surge 配置", origName)
	}
	// Resolve script bodies (download remote script-paths, cache +
	// fingerprint them) so the JS engine can run offline afterwards.
	imp.Report.Notes = append(imp.Report.Notes, imp.ResolveScripts()...)
	if len(imp.Engine.Scripts) > 0 {
		imp.Report.Notes = append(imp.Report.Notes,
			script.Describe(script.FromEngine(&imp.Engine)))
	}
	if err := surge.SaveImported(imp, m.importedPath()); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.sourceKind = "surge"
	m.sourceName = origName
	m.sourceAt = imp.ImportedAt
	running := m.cmd != nil
	m.mu.Unlock()
	meta := sourceMeta{Kind: "surge", SourceName: origName, At: imp.ImportedAt}
	if raw, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(m.sourceMetaPath(), raw, 0o644)
	}
	rep := imp.Report
	if running {
		if err := m.Restart(); err != nil {
			return &rep, fmt.Errorf("导入已保存，但内核重启失败：%w", err)
		}
	}
	return &rep, nil
}

// ImportReport returns the persisted report of the active Surge
// import, if any.
func (m *Manager) ImportReport() *surge.Report {
	if m.sourceKind != "surge" {
		return nil
	}
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil {
		return nil
	}
	return &imp.Report
}

// Mode returns the current routing mode (rule|global|direct).
func (m *Manager) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetMode persists the routing mode and, if the core is running,
// restarts it with a regenerated config (app-level mode switching:
// sing-box's clash API mode-list only contains "rule" on plain configs).
func (m *Manager) SetMode(mode string) error {
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("mode must be rule|global|direct")
	}
	m.mu.Lock()
	m.mode = mode
	running := m.cmd != nil
	m.mu.Unlock()
	raw, _ := json.Marshal(map[string]string{"mode": mode})
	if err := os.WriteFile(m.modePath(), raw, 0o644); err != nil {
		return err
	}
	if running {
		return m.Restart()
	}
	return nil
}

func (m *Manager) configPath() string { return filepath.Join(m.appDir, "sing-box-config.json") }
func (m *Manager) logPath() string    { return filepath.Join(m.appDir, "sakunet-core.log") }

// FindBinary locates sing-box: app dir, cwd, then PATH.
func (m *Manager) FindBinary() (string, error) {
	name := "sing-box"
	if os.PathSeparator == '\\' {
		name = "sing-box.exe"
	}
	for _, cand := range []string{
		filepath.Join(m.appDir, name),
		filepath.Join(m.appDir, "sing-box.exe"),
	} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand, nil
		}
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("sing-box binary not found (put sing-box.exe next to SakuNet.exe — see fetch-core.ps1 — or add sing-box to PATH)")
}

// Start generates the config, validates it with `sing-box check`,
// then launches the sidecar.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return fmt.Errorf("core already running")
	}
	bin, err := m.FindBinary()
	if err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.binary = bin
	if err := m.generate(); err != nil {
		m.lastErr = err.Error()
		return fmt.Errorf("generate config: %w", err)
	}
	if out, err := exec.Command(bin, "check", "-c", m.configPath()).CombinedOutput(); err != nil {
		m.lastErr = fmt.Sprintf("sing-box check failed: %s", out)
		return fmt.Errorf("sing-box check failed: %s", out)
	}
	logFile, err := os.OpenFile(m.logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, "run", "-c", m.configPath())
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = m.appDir
	if err := cmd.Start(); err != nil {
		logFile.Close()
		m.lastErr = err.Error()
		return err
	}
	m.cmd = cmd
	m.done = make(chan struct{})
	m.lastErr = ""
	go func(c *exec.Cmd, f *os.File, done chan struct{}) {
		_ = c.Wait()
		f.Close()
		close(done)
	}(cmd, logFile, m.done)
	if out, err := exec.Command(bin, "version").CombinedOutput(); err == nil {
		m.version = firstLine(string(out))
	}
	m.startEngineLocked()
	return nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

// Stop terminates the sidecar if running.
func (m *Manager) Stop() error {
	m.mu.Lock()
	m.stopEngineLocked()
	cmd, done := m.cmd, m.done
	m.cmd = nil
	m.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		<-done
	}
	return nil
}

// Restart stops (if needed) and starts the core again.
func (m *Manager) Restart() error {
	_ = m.Stop()
	return m.Start()
}

// ScriptLogs returns the JS engine's recent log entries and
// notifications for the settings page. Empty when no runner is up.
func (m *Manager) ScriptLogs() (logs []script.LogEntry, notes []script.Notification) {
	m.mu.Lock()
	r := m.scriptRunner
	m.mu.Unlock()
	if r == nil {
		return []script.LogEntry{}, []script.Notification{}
	}
	return r.Logs(), r.Notifications()
}

// Status reports the sidecar state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scriptRunner != nil && m.mitmInfo != nil {
		m.mitmInfo.Scripts = m.scriptRunner.Infos()
	}
	st := Status{Mode: m.mode, Binary: m.binary, NodesFile: m.nodesPath, Version: m.version, Error: m.lastErr,
		SourceKind: m.sourceKind, SourceName: m.sourceName, Tun: m.tun, MITM: m.mitmInfo}
	st.Configured = m.sourceKind == "surge"
	if !st.Configured {
		if _, err := os.Stat(m.nodesPath); err == nil {
			st.Configured = true
		}
	}
	if !m.sourceAt.IsZero() {
		st.SourceAt = m.sourceAt.Format("2006-01-02 15:04")
	}
	if m.cmd != nil && m.cmd.Process != nil {
		select {
		case <-m.done:
			st.Running = false
		default:
			st.Running = true
			st.PID = m.cmd.Process.Pid
		}
	}
	return st
}
