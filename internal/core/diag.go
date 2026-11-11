package core

import (
	"encoding/json"
	"os"
	"strings"

	"sakunet/internal/config"
	"sakunet/internal/surge"
)

// ConfigSummary is a credential-free structural summary of the
// generated sing-box config, for the self-check and diagnostics
// bundle: counts and shapes only, never addresses or secrets.
type ConfigSummary struct {
	Exists     bool `json:"exists"`
	Inbounds   int  `json:"inbounds"`
	Outbounds  int  `json:"outbounds"`
	Groups     int  `json:"groups"`
	Nodes      int  `json:"nodes"`
	RuleSets   int  `json:"rule_sets"`
	RouteRules int  `json:"route_rules"`
	HasTun     bool `json:"has_tun"`
}

// ConfigSummary reads the generated config file (structure only).
func (m *Manager) ConfigSummary() ConfigSummary {
	var sum ConfigSummary
	raw, err := os.ReadFile(m.configPath())
	if err != nil {
		return sum
	}
	var cfg struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []struct {
			Type string `json:"type"`
		} `json:"outbounds"`
		Route struct {
			RuleSet []any `json:"rule_set"`
			Rules   []any `json:"rules"`
		} `json:"route"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return sum
	}
	sum.Exists = true
	sum.Inbounds = len(cfg.Inbounds)
	sum.Outbounds = len(cfg.Outbounds)
	sum.RuleSets = len(cfg.Route.RuleSet)
	sum.RouteRules = len(cfg.Route.Rules)
	for _, in := range cfg.Inbounds {
		if in["type"] == "tun" {
			sum.HasTun = true
		}
	}
	for _, ob := range cfg.Outbounds {
		switch ob.Type {
		case "selector", "urltest":
			sum.Groups++
		case "direct", "block", "dns":
		default:
			sum.Nodes++
		}
	}
	return sum
}

// Secrets collects every credential value of the active stores for
// the diagnostics redactor: node server addresses and credentials,
// imported CA material. The values are used ONLY to scrub them out
// of exported text; they are never written anywhere by this path.
func (m *Manager) Secrets() []string {
	var out []string
	addNode := func(n *config.Node) {
		for _, v := range []string{n.Server, n.Password, n.PSK, n.UUID, n.Username, n.ObfsPassword, n.RealityPublicKey} {
			if len(v) >= 4 { // tiny values would over-redact prose
				out = append(out, v)
			}
		}
	}
	if f, err := config.Load(m.nodesPath); err == nil {
		for i := range f.Nodes {
			addNode(&f.Nodes[i])
		}
	}
	if m.sourceKind == "surge" {
		if imp, err := surge.LoadImported(m.importedPath()); err == nil {
			for i := range imp.Nodes {
				addNode(&imp.Nodes[i])
			}
			for _, v := range imp.Engine.MITMParams {
				if len(v) >= 4 {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// CoreLogTail returns the last n lines of the sing-box sidecar log.
func (m *Manager) CoreLogTail(n int) string {
	raw, err := os.ReadFile(m.logPath())
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// AppVersion returns the sing-box version string once known.
func (m *Manager) CoreVersion() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version
}
