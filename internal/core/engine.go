package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"sakunet/internal/config"
	"sakunet/internal/mitm"
	"sakunet/internal/surge"
)

// MITMInfo is the panel-facing state of the MITM/rewrite engine.
type MITMInfo struct {
	State         string                  `json:"state"` // running | standby
	Reason        string                  `json:"reason,omitempty"`
	Addr          string                  `json:"addr,omitempty"`
	Hostnames     int                     `json:"hostnames"`
	RulesOK       int                     `json:"rules_ok"`
	Unsupported   []surge.UnsupportedRule `json:"unsupported,omitempty"`
	CASubject     string                  `json:"ca_subject,omitempty"`
	CAExpiry      string                  `json:"ca_expiry,omitempty"`
	CAFingerprint string                  `json:"ca_fingerprint,omitempty"` // SHA-256, hex with colons
}

type prefs struct {
	Tun bool `json:"tun"`
}

func (m *Manager) prefsPath() string { return filepath.Join(m.appDir, "sakunet-prefs.json") }

func (m *Manager) loadPrefs() {
	if raw, err := os.ReadFile(m.prefsPath()); err == nil {
		var p prefs
		if json.Unmarshal(raw, &p) == nil {
			m.tun = p.Tun
		}
	}
}

func (m *Manager) savePrefs() error {
	raw, _ := json.Marshal(prefs{Tun: m.tun})
	return os.WriteFile(m.prefsPath(), raw, 0o600)
}

// Tun reports the TUN preference.
func (m *Manager) Tun() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tun
}

// SetTun persists the TUN preference and restarts the core if it is
// running (the inbound set is part of the generated config).
func (m *Manager) SetTun(on bool) error {
	m.mu.Lock()
	m.tun = on
	running := m.cmd != nil
	m.mu.Unlock()
	if err := m.savePrefs(); err != nil {
		return err
	}
	if running {
		return m.Restart()
	}
	return nil
}

// startEngineLocked brings up the MITM layer when the imported
// config carries engine data. It never fails the core start: any
// problem is recorded as a standby reason for the panel.
func (m *Manager) startEngineLocked() {
	m.mitmInfo = &MITMInfo{State: "standby"}
	if m.sourceKind != "surge" {
		m.mitmInfo.Reason = "未导入 Surge 配置，无引擎数据"
		return
	}
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil {
		m.mitmInfo.Reason = "导入数据读取失败：" + err.Error()
		return
	}
	ce := imp.Engine.Compile()
	m.mitmInfo.RulesOK = len(ce.Rules)
	m.mitmInfo.Unsupported = ce.Unsupported
	m.mitmInfo.Hostnames = len(imp.Engine.MITMHostnames)

	caCert, caX509, caErr := mitm.LoadCA(imp.Engine.MITMParams)
	hostnames := imp.Engine.MITMHostnames
	if caErr != nil {
		// Without a CA the HTTPS half cannot run; the layer still
		// serves plain-HTTP rewrites when rules exist.
		hostnames = nil
		m.mitmInfo.Reason = caErr.Error()
	} else {
		m.mitmInfo.CASubject = caX509.Subject.String()
		m.mitmInfo.CAExpiry = caX509.NotAfter.Format("2006-01-02")
		sum := sha256.Sum256(caX509.Raw)
		m.mitmInfo.CAFingerprint = colonHex(sum[:])
	}
	if len(hostnames) == 0 && len(ce.Rules) == 0 {
		if m.mitmInfo.Reason == "" {
			m.mitmInfo.Reason = "配置无 MITM 主机名与重写规则"
		}
		return
	}
	srv, err := mitm.Start(mitm.Config{
		Hostnames:     hostnames,
		Engine:        ce,
		CA:            caCert,
		UpstreamProxy: "127.0.0.1:2080",
		Log:           log.New(os.Stderr, "", log.LstdFlags),
	}, "127.0.0.1:2081")
	if err != nil {
		m.mitmInfo.Reason = "MITM 层启动失败：" + err.Error()
		return
	}
	m.mitmSrv = srv
	m.mitmInfo.State = "running"
	m.mitmInfo.Addr = srv.Addr()
	if caErr != nil {
		m.mitmInfo.Reason = "仅明文 HTTP 重写生效；HTTPS 解密待机：" + caErr.Error()
	}
}

func (m *Manager) stopEngineLocked() {
	if m.mitmSrv != nil {
		m.mitmSrv.Close()
		m.mitmSrv = nil
	}
	if m.mitmInfo != nil {
		m.mitmInfo.State = "standby"
		m.mitmInfo.Addr = ""
	}
}

// SysproxyAddr is where the OS system proxy should point: the MITM
// layer when it runs (so traffic passes the engine first), else
// the sing-box mixed inbound directly.
func (m *Manager) SysproxyAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mitmSrv != nil {
		return m.mitmSrv.Addr()
	}
	return "127.0.0.1:2080"
}

// EngineCA returns the imported CA certificate (DER, public part
// only) for the panel's "install CA" download.
func (m *Manager) EngineCA() ([]byte, error) {
	if m.sourceKind != "surge" {
		return nil, fmt.Errorf("未导入 Surge 配置")
	}
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil {
		return nil, err
	}
	_, caX509, err := mitm.LoadCA(imp.Engine.MITMParams)
	if err != nil {
		return nil, err
	}
	return caX509.Raw, nil
}

func colonHex(b []byte) string {
	h := hex.EncodeToString(b)
	out := ""
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			out += ":"
		}
		out += h[i : i+2]
	}
	return out
}

// ImportNodes merges link/subscription-parsed nodes into the active
// configuration store (imported Surge model when active, else
// nodes.json), deduplicating by type+server+port, and restarts the
// core if running. Returns how many nodes were added.
func (m *Manager) ImportNodes(nodes []*config.Node) (int, error) {
	if len(nodes) == 0 {
		return 0, fmt.Errorf("没有可导入的节点")
	}
	key := func(n *config.Node) string {
		return fmt.Sprintf("%s|%s|%d", n.Type, n.Server, n.Port)
	}
	added := 0
	if m.sourceKind == "surge" {
		imp, err := surge.LoadImported(m.importedPath())
		if err != nil {
			return 0, err
		}
		have := map[string]bool{}
		names := map[string]int{}
		for i := range imp.Nodes {
			have[key(&imp.Nodes[i])] = true
			names[imp.Nodes[i].Name]++
		}
		for _, n := range nodes {
			if have[key(n)] {
				continue
			}
			have[key(n)] = true
			name := n.Name
			names[name]++
			if names[name] > 1 {
				name = fmt.Sprintf("%s-%d", name, names[name])
			}
			cp := *n
			cp.Name, cp.Tag = name, name
			imp.Nodes = append(imp.Nodes, cp)
			added++
		}
		if added > 0 {
			imp.Report.NodesOK += added
			imp.Report.Notes = append(imp.Report.Notes,
				fmt.Sprintf("分享链接/订阅导入：新增节点 %d 个", added))
			if err := surge.SaveImported(imp, m.importedPath()); err != nil {
				return 0, err
			}
		}
	} else {
		f := &config.File{Tun: m.tun}
		if raw, err := os.ReadFile(m.nodesPath); err == nil {
			_ = json.Unmarshal(raw, f)
		}
		have := map[string]bool{}
		names := map[string]int{}
		for i := range f.Nodes {
			have[key(&f.Nodes[i])] = true
			names[f.Nodes[i].Name]++
		}
		for _, n := range nodes {
			if have[key(n)] {
				continue
			}
			have[key(n)] = true
			name := n.Name
			names[name]++
			if names[name] > 1 {
				name = fmt.Sprintf("%s-%d", name, names[name])
			}
			cp := *n
			cp.Name, cp.Tag = name, name
			f.Nodes = append(f.Nodes, cp)
			added++
		}
		if added > 0 {
			raw, err := json.MarshalIndent(f, "", "  ")
			if err != nil {
				return 0, err
			}
			if err := os.WriteFile(m.nodesPath, append(raw, '\n'), 0o600); err != nil {
				return 0, err
			}
		}
	}
	if added > 0 {
		m.mu.Lock()
		running := m.cmd != nil
		m.mu.Unlock()
		if running {
			if err := m.Restart(); err != nil {
				return added, fmt.Errorf("节点已保存，但内核重启失败：%w", err)
			}
		}
	}
	return added, nil
}

// ImportModule merges a .sgmodule file's MITM hostnames and URL
// Rewrite rules into the active Surge import's engine data.
func (m *Manager) ImportModule(name string, data []byte) (*surge.ModuleResult, error) {
	if m.sourceKind != "surge" {
		return nil, fmt.Errorf("请先导入 Surge 配置，模块并入其引擎数据")
	}
	imp, err := surge.LoadImported(m.importedPath())
	if err != nil {
		return nil, err
	}
	mr := surge.ParseModule(name, data)
	imp.MergeModule(mr)
	if err := surge.SaveImported(imp, m.importedPath()); err != nil {
		return nil, err
	}
	m.mu.Lock()
	running := m.cmd != nil
	m.mu.Unlock()
	if running {
		if err := m.Restart(); err != nil {
			return mr, fmt.Errorf("模块已保存，但内核重启失败：%w", err)
		}
	}
	return mr, nil
}
