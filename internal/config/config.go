// Package config loads SakuNet's local nodes.json and generates a
// sing-box (>= 1.14) configuration that wires the nodes into selector
// groups and routes traffic through the remote rule-sets published in
// github.com/slynnnn/surge-rules (platforms/singbox).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Node is one proxy server entry in nodes.json.
type Node struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // snell|anytls|hysteria2|naive|vless|vmess|trojan|shadowsocks
	Server  string `json:"server"`
	Port    int    `json:"port"`
	PSK     string `json:"psk,omitempty"`     // snell
	Version int    `json:"version,omitempty"` // snell: 5 or 6 (5 is spoken as 4, see outbound())
	Mode    string `json:"mode,omitempty"`    // snell v6: default|unshaped|unsafe-raw

	Password string `json:"password,omitempty"` // anytls/hysteria2/naive/trojan/shadowsocks
	Username string `json:"username,omitempty"` // naive
	UUID     string `json:"uuid,omitempty"`     // vless/vmess
	Flow     string `json:"flow,omitempty"`     // vless
	AlterID  int    `json:"alter_id,omitempty"` // vmess
	Security string `json:"security,omitempty"` // vmess cipher (auto default)

	Method       string `json:"method,omitempty"` // shadowsocks cipher
	ObfsPassword string `json:"obfs_password,omitempty"`

	SNI              string `json:"sni,omitempty"`
	Insecure         bool   `json:"insecure,omitempty"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortID   string `json:"reality_short_id,omitempty"`
	TFO              bool   `json:"tfo,omitempty"` // TCP Fast Open (dialer option)
	Tag              string `json:"-"`             // resolved unique outbound tag
}

// File is the on-disk shape of nodes.json.
type File struct {
	Tun   bool   `json:"tun"`
	Nodes []Node `json:"nodes"`
}

// Load reads and validates a nodes.json file and resolves unique tags.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(f.Nodes) == 0 {
		return nil, fmt.Errorf("%s: no nodes defined", path)
	}
	seen := map[string]int{}
	for i := range f.Nodes {
		n := &f.Nodes[i]
		if n.Name == "" || n.Server == "" || n.Port == 0 {
			return nil, fmt.Errorf("%s: node #%d missing name/server/port", path, i+1)
		}
		tag := n.Name
		seen[tag]++
		if seen[tag] > 1 {
			tag = fmt.Sprintf("%s-%d", tag, seen[tag])
		}
		n.Tag = tag
	}
	return &f, nil
}

func tlsBlock(n *Node) map[string]any {
	tls := map[string]any{"enabled": true}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	}
	if n.Insecure {
		tls["insecure"] = true
	}
	if n.RealityPublicKey != "" {
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": n.RealityPublicKey,
			"short_id":   n.RealityShortID,
		}
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	return tls
}

// outbound converts one Node into a sing-box outbound object.
func outbound(n *Node) (map[string]any, error) {
	ob := map[string]any{
		"type":        n.Type,
		"tag":         n.Tag,
		"server":      n.Server,
		"server_port": n.Port,
	}
	if n.TFO {
		ob["tcp_fast_open"] = true
	}
	switch n.Type {
	case "snell":
		// sing-box outbound speaks Snell 4 or 6. A v5 server uses the v4
		// TCP wire protocol (v5 only adds QUIC Proxy Mode, unsupported),
		// so version 5 in nodes.json is emitted as 4.
		v := n.Version
		switch v {
		case 6:
			ob["version"] = 6
			mode := n.Mode
			if mode == "" {
				mode = "default"
			}
			ob["mode"] = mode
		case 4, 5:
			ob["version"] = 4
		default:
			return nil, fmt.Errorf("node %s: snell version must be 5 or 6, got %d", n.Name, v)
		}
		if n.PSK == "" {
			return nil, fmt.Errorf("node %s: snell psk is required", n.Name)
		}
		ob["psk"] = n.PSK
	case "anytls":
		ob["password"] = n.Password
		ob["tls"] = tlsBlock(n)
	case "hysteria2":
		ob["password"] = n.Password
		if n.ObfsPassword != "" {
			ob["obfs"] = map[string]any{"type": "salamander", "password": n.ObfsPassword}
		}
		ob["tls"] = tlsBlock(n)
	case "naive":
		ob["username"] = n.Username
		ob["password"] = n.Password
		ob["tls"] = tlsBlock(n)
	case "vless":
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
		if n.SNI != "" || n.RealityPublicKey != "" || n.Flow != "" {
			ob["tls"] = tlsBlock(n)
		}
	case "vmess":
		ob["uuid"] = n.UUID
		sec := n.Security
		if sec == "" {
			sec = "auto"
		}
		ob["security"] = sec
		ob["alter_id"] = n.AlterID
		if n.SNI != "" {
			ob["tls"] = tlsBlock(n)
		}
	case "trojan":
		ob["password"] = n.Password
		ob["tls"] = tlsBlock(n)
	case "shadowsocks":
		ob["method"] = n.Method
		ob["password"] = n.Password
	default:
		return nil, fmt.Errorf("node %s: unsupported type %q", n.Name, n.Type)
	}
	return ob, nil
}

const ruleSetBase = "https://raw.githubusercontent.com/slynnnn/surge-rules/main/platforms/singbox/merged/"

// Build renders the complete sing-box configuration for the loaded nodes.
// mode is the routing mode: "rule" (rule-set based split routing),
// "global" (everything via 节点选择), or "direct" (everything direct).
// sing-box's clash API cannot switch modes on a plain config (its
// mode-list only contains "rule"), so SakuNet implements mode switching
// at the app layer: regenerate the route section and restart the core.
func Build(f *File, mode string) (map[string]any, error) {
	tags := make([]string, 0, len(f.Nodes))
	outbounds := []any{}
	selector := func(tag string, members []string) map[string]any {
		return map[string]any{
			"type":      "selector",
			"tag":       tag,
			"outbounds": members,
			"default":   members[0],
		}
	}
	nodeOutbounds := []any{}
	for i := range f.Nodes {
		ob, err := outbound(&f.Nodes[i])
		if err != nil {
			return nil, err
		}
		tags = append(tags, f.Nodes[i].Tag)
		nodeOutbounds = append(nodeOutbounds, ob)
	}
	mainMembers := append(append([]string{}, tags...), "direct")
	outbounds = append(outbounds,
		selector("节点选择", mainMembers),
		selector("AI", tags),
		selector("流媒体", tags),
		selector("社交", tags),
		selector("漏网之鱼", tags),
	)
	outbounds = append(outbounds, nodeOutbounds...)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	ruleSet := func(tag, file string) map[string]any {
		return map[string]any{
			"type":            "remote",
			"tag":             tag,
			"format":          "source",
			"url":             ruleSetBase + file,
			"download_detour": "direct",
			"update_interval": "24h",
		}
	}

	inbounds := []any{
		map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 2080,
		},
	}
	if f.Tun {
		inbounds = append(inbounds, map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route":   true,
			"strict_route": true,
			"stack":        "mixed",
		})
	}

	cfg := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": "节点选择"},
				map[string]any{"type": "https", "tag": "dns-local", "server": "223.5.5.5"},
			},
			"rules": []any{
				// Rule-set downloads must resolve even if every node is down:
				// their hostnames always go to the direct local DNS.
				map[string]any{"domain": []string{"raw.githubusercontent.com"}, "action": "route", "server": "dns-local"},
				map[string]any{"rule_set": []string{"china"}, "action": "route", "server": "dns-local"},
			},
			"final":    "dns-remote",
			"strategy": "prefer_ipv4",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rule_set": []any{
				ruleSet("ads", "ads.json"),
				ruleSet("ai", "ai.json"),
				ruleSet("streaming", "streaming.json"),
				ruleSet("social", "social.json"),
				ruleSet("global", "global.json"),
				ruleSet("china", "china.json"),
			},
			"rules":                 routeRules(mode),
			"auto_detect_interface": true,
			"final":                 routeFinal(mode),
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

// routeRules returns the route rule list for the given routing mode.
func routeRules(mode string) []any {
	base := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	if mode != "rule" {
		return base
	}
	return append(base,
		map[string]any{"rule_set": []string{"ads"}, "action": "reject"},
		map[string]any{"rule_set": []string{"ai"}, "outbound": "AI"},
		map[string]any{"rule_set": []string{"streaming"}, "outbound": "流媒体"},
		map[string]any{"rule_set": []string{"social"}, "outbound": "社交"},
		map[string]any{"rule_set": []string{"global"}, "outbound": "节点选择"},
		map[string]any{"rule_set": []string{"china"}, "outbound": "direct"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
	)
}

func routeFinal(mode string) string {
	switch mode {
	case "global":
		return "节点选择"
	case "direct":
		return "direct"
	default:
		return "漏网之鱼"
	}
}

// Generate loads nodesPath and writes the sing-box config JSON to outPath.
func Generate(nodesPath, outPath string, mode string) error {
	f, err := Load(nodesPath)
	if err != nil {
		return err
	}
	cfg, err := Build(f, mode)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, append(raw, '\n'), 0o644)
}

// Tags is a small helper for logging/tests.
func (f *File) Tags() []string {
	tags := make([]string, 0, len(f.Nodes))
	for i := range f.Nodes {
		tags = append(tags, f.Nodes[i].Tag)
	}
	return tags
}

var _ = strings.TrimSpace
