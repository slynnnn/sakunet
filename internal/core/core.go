// Package core manages the sing-box sidecar process lifecycle.
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"sakunet/internal/config"
)

type Status struct {
	Mode      string `json:"mode"`
	Running   bool   `json:"running"`
	PID       int    `json:"pid,omitempty"`
	Binary    string `json:"binary,omitempty"`
	NodesFile string `json:"nodes_file,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Manager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	appDir    string
	nodesPath string
	binary    string
	version   string
	lastErr   string
	mode      string
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
	m := &Manager{appDir: dir, nodesPath: nodesPath, mode: "rule"}
	if raw, err := os.ReadFile(m.modePath()); err == nil {
		var v struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(raw, &v) == nil && (v.Mode == "global" || v.Mode == "direct") {
			m.mode = v.Mode
		}
	}
	return m, nil
}

func (m *Manager) modePath() string { return filepath.Join(m.appDir, "sakunet-mode.json") }

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
	if err := config.Generate(m.nodesPath, m.configPath(), m.mode); err != nil {
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

// Status reports the sidecar state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Mode: m.mode, Binary: m.binary, NodesFile: m.nodesPath, Version: m.version, Error: m.lastErr}
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
