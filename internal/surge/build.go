package surge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"sakunet/internal/config"
)

// mainTarget is the imported config's principal outbound: the FINAL
// policy when present, else the first group, else the first node.
func mainTarget(imp *Imported) string {
	if imp.Final != "" {
		return imp.Final
	}
	if len(imp.Groups) > 0 {
		return imp.Groups[0].Name
	}
	if len(imp.Nodes) > 0 {
		return imp.Nodes[0].Tag
	}
	return "direct"
}

// BuildImported renders the complete sing-box configuration for an
// Imported model. The imported config is the single source of
// truth: outbounds are exactly its groups and nodes, route rules
// are exactly its converted [Rule] lines (plus sniff/hijack
// plumbing), and the only rule-sets are the ones its own RULE-SET
// lines referenced. SakuNet overlays nothing of its own here; the
// built-in rule-set routing exists only in the nodes.json fallback
// path (config.Build).
func BuildImported(imp *Imported, mode string) (map[string]any, error) {
	return BuildImportedTun(imp, mode, false)
}

// BuildImportedTun is BuildImported with an optional TUN inbound.
func BuildImportedTun(imp *Imported, mode string, tun bool) (map[string]any, error) {
	outbounds := []any{}
	for i := range imp.Groups {
		outbounds = append(outbounds, imp.Groups[i].Outbound())
	}
	for i := range imp.Nodes {
		ob, err := config.OutboundFor(&imp.Nodes[i])
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, ob)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	final := "direct"
	switch mode {
	case "global":
		final = mainTarget(imp)
	case "direct":
		final = "direct"
	default: // rule
		for _, r := range imp.Rules {
			rules = append(rules, r)
		}
		final = mainTarget(imp)
	}

	ruleSetDefs := []any{}
	for _, rs := range imp.ExtraRuleSets {
		ruleSetDefs = append(ruleSetDefs, rs)
	}

	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": mainTarget(imp)},
				map[string]any{"type": "https", "tag": "dns-local", "server": "223.5.5.5"},
			},
			"rules": []any{
				// Rule-set downloads must resolve even if every node
				// is down: their hostnames always use direct DNS.
				map[string]any{"domain": []string{"raw.githubusercontent.com"}, "action": "route", "server": "dns-local"},
			},
			"final":    "dns-remote",
			"strategy": "prefer_ipv4",
		},
		"inbounds":  importedInbounds(tun),
		"outbounds": outbounds,
		"route": map[string]any{
			"rule_set":              ruleSetDefs,
			"rules":                 rules,
			"auto_detect_interface": true,
			"final":                 final,
			"default_domain_resolver": map[string]any{
				"server": "dns-local",
			},
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9090",
				"default_mode":        "rule",
			},
			"cache_file": map[string]any{"enabled": true, "path": "cache.db"},
		},
	}
	return cfg, nil
}

// SaveImported persists the import model as JSON.
func SaveImported(imp *Imported, path string) error {
	raw, err := json.MarshalIndent(imp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// LoadImported reads a persisted import model. Rules and rule-set
// definitions are decoded with UseNumber so integer fields (ports)
// keep their exact literal form for sing-box.
func LoadImported(path string) (*Imported, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var imp Imported
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&imp); err != nil {
		return nil, err
	}
	// Re-decode the raw fragments with number preservation.
	var probe struct {
		Rules         []json.RawMessage `json:"rules"`
		ExtraRuleSets []json.RawMessage `json:"extra_rule_sets"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil {
		decodeFrag := func(r json.RawMessage) map[string]any {
			d := json.NewDecoder(bytes.NewReader(r))
			d.UseNumber()
			var m map[string]any
			if err := d.Decode(&m); err != nil {
				return nil
			}
			return m
		}
		imp.Rules = nil
		for _, r := range probe.Rules {
			if m := decodeFrag(r); m != nil {
				imp.Rules = append(imp.Rules, m)
			}
		}
		imp.ExtraRuleSets = nil
		for _, r := range probe.ExtraRuleSets {
			if m := decodeFrag(r); m != nil {
				imp.ExtraRuleSets = append(imp.ExtraRuleSets, m)
			}
		}
	}
	if len(imp.Nodes) == 0 && len(imp.Groups) == 0 {
		return nil, fmt.Errorf("%s: empty import", path)
	}
	return &imp, nil
}

// importedInbounds renders the mixed inbound plus, when tun is on,
// a TUN inbound (same shape as the nodes.json path).
func importedInbounds(tun bool) []any {
	in := []any{
		map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 2080,
		},
	}
	if tun {
		in = append(in, map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": true,
			"stack":        "mixed",
		})
	}
	return in
}

// GenerateImported loads a persisted import and writes the sing-box
// config JSON to outPath.
func GenerateImported(importedPath, outPath, mode string, tun ...bool) error {
	imp, err := LoadImported(importedPath)
	if err != nil {
		return err
	}
	cfg, err := BuildImportedTun(imp, mode, len(tun) > 0 && tun[0])
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, append(raw, '\n'), 0o644)
}
