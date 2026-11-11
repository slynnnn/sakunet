package config

import (
	"path/filepath"
	"testing"
)

func loadExample(t *testing.T) *File {
	t.Helper()
	f, err := Load(filepath.Join("..", "..", "nodes.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBuildModes(t *testing.T) {
	f := loadExample(t)
	for mode, wantFinal := range map[string]string{
		"rule": "漏网之鱼", "global": "节点选择", "direct": "direct",
	} {
		cfg, err := Build(f, mode)
		if err != nil {
			t.Fatal(err)
		}
		route := cfg["route"].(map[string]any)
		if route["final"] != wantFinal {
			t.Errorf("mode %s: final = %v, want %s", mode, route["final"], wantFinal)
		}
		rules := route["rules"].([]any)
		if mode == "rule" && len(rules) < 5 {
			t.Errorf("rule mode should carry rule-set rules, got %d", len(rules))
		}
		if mode != "rule" && len(rules) != 2 {
			t.Errorf("mode %s should only keep sniff+hijack, got %d rules", mode, len(rules))
		}
	}
}

func TestSnellVersionMapping(t *testing.T) {
	f := loadExample(t)
	ob, err := outbound(&f.Nodes[0]) // snell v6 example
	if err != nil {
		t.Fatal(err)
	}
	if ob["version"] != 6 || ob["mode"] != "default" {
		t.Errorf("snell v6 outbound = %v", ob)
	}
	n := Node{Name: "x", Type: "snell", Server: "192.0.2.1", Port: 1, PSK: "123456789012", Version: 5}
	ob, err = outbound(&n)
	if err != nil {
		t.Fatal(err)
	}
	if ob["version"] != 4 {
		t.Errorf("snell v5 must be spoken as 4, got %v", ob["version"])
	}
}
