package surge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseFixture(t *testing.T) *Imported {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fixture.conf"))
	if err != nil {
		t.Fatal(err)
	}
	imp, err := Parse("fixture.conf", raw)
	if err != nil {
		t.Fatal(err)
	}
	return imp
}

func TestParseFixture(t *testing.T) {
	imp := parseFixture(t)
	rep := imp.Report
	if rep.NodesOK != 3 || rep.NodesSkipped != 0 {
		t.Errorf("nodes ok/skipped = %d/%d, want 3/0", rep.NodesOK, rep.NodesSkipped)
	}
	if rep.GroupsOK != 2 {
		t.Errorf("groups ok = %d, want 2", rep.GroupsOK)
	}
	// 3 DOMAIN-family + 2 mapped RULE-SET + IP-CIDR + DEST-PORT + FINAL.
	if rep.RulesOK != 8 {
		t.Errorf("rules ok = %d, want 8", rep.RulesOK)
	}
	// External RULE-SET + USER-AGENT are not migrated.
	if len(rep.Unmigrated) != 2 {
		t.Errorf("unmigrated = %d (%v), want 2", len(rep.Unmigrated), rep.Unmigrated)
	}
	snell := imp.Nodes[0]
	if snell.Type != "snell" || snell.Version != 6 || snell.Mode != "default" || !snell.TFO {
		t.Errorf("snell node = %+v", snell)
	}
	anytls := imp.Nodes[1]
	if anytls.Type != "anytls" || !anytls.Insecure || anytls.SNI != "example.com" {
		t.Errorf("anytls node = %+v", anytls)
	}
	// snell params with no sing-box equivalent are summarised, not dropped.
	joined := strings.Join(rep.IgnoredParams, " ")
	if !strings.Contains(joined, "snell.reuse") || !strings.Contains(joined, "snell.ecn") {
		t.Errorf("ignored params = %v", rep.IgnoredParams)
	}
	auto := imp.Groups[1]
	if auto.Kind != "urltest" || auto.Interval != "600s" || auto.Tolerance != 100 {
		t.Errorf("url-test group = %+v", auto)
	}
	if imp.Final != "Main" {
		t.Errorf("final = %q, want Main", imp.Final)
	}
	// Engine-backed sections are parsed and preserved, listed as
	// pending — never as unmigrated.
	if len(rep.EnginePending) != 3 {
		t.Fatalf("engine pending = %v, want 3 sections", rep.EnginePending)
	}
	pend := map[string]int{}
	for _, p := range rep.EnginePending {
		pend[p.Section] = p.Count
	}
	if pend["MITM"] != 2 || pend["URL Rewrite"] != 1 || pend["Script"] != 1 {
		t.Errorf("engine pending counts = %v, want MITM 2 / URL Rewrite 1 / Script 1", pend)
	}
	if len(imp.Engine.MITMHostnames) != 2 || len(imp.Engine.URLRewrites) != 1 ||
		imp.Engine.URLRewrites[0].Kind != "302" || len(imp.Engine.Scripts) != 1 {
		t.Errorf("engine data = %+v", imp.Engine)
	}
	// Both RULE-SET lines become rule-set definitions of the
	// generated config: the service set and the merged ai set.
	if len(imp.ExtraRuleSets) != 2 {
		t.Fatalf("extra rule sets = %v, want 2", imp.ExtraRuleSets)
	}
	tags := map[string]bool{}
	for _, rs := range imp.ExtraRuleSets {
		tags[rs["tag"].(string)] = true
	}
	if !tags["sr-service-netflix"] || !tags["ai"] {
		t.Errorf("extra rule set tags = %v", tags)
	}
}

func TestBuildFixture(t *testing.T) {
	imp := parseFixture(t)
	cfg, err := BuildImported(imp, "rule")
	if err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "Main" {
		t.Errorf("route final = %v, want Main", route["final"])
	}
	// Config-driven doctrine: nothing of SakuNet's own is overlaid.
	// Outbounds are exactly the fixture's groups + nodes + direct.
	for _, ob := range cfg["outbounds"].([]any) {
		tag := ob.(map[string]any)["tag"]
		switch tag {
		case "节点选择", "AI", "流媒体", "社交", "漏网之鱼":
			t.Errorf("built-in group %v must not appear in imported config", tag)
		}
	}
	// Route rules: sniff + hijack-dns + the 7 converted rules.
	rules := route["rules"].([]any)
	if len(rules) != 9 {
		t.Errorf("route rules = %d, want 9 (2 plumbing + 7 converted)", len(rules))
	}
	if _, ok := rules[2].(map[string]any)["domain"]; !ok {
		t.Errorf("first converted rule should be the DOMAIN rule, got %v", rules[2])
	}
	// Rule-set definitions: only the two the fixture itself named.
	defs := route["rule_set"].([]any)
	if len(defs) != 2 {
		t.Errorf("rule_set defs = %d, want 2 (fixture's own references)", len(defs))
	}
	if out := os.Getenv("SAKUNET_FIXTURE_OUT"); out != "" {
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	imp := parseFixture(t)
	path := filepath.Join(t.TempDir(), "imported.json")
	if err := SaveImported(imp, path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadImported(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Report.NodesOK != 3 || len(back.Rules) != len(imp.Rules) {
		t.Errorf("round trip mismatch: %+v vs %d rules", back.Report, len(imp.Rules))
	}
	if len(back.Engine.MITMHostnames) != 2 || len(back.Engine.URLRewrites) != 1 || len(back.Engine.Scripts) != 1 {
		t.Errorf("engine data lost in round trip: %+v", back.Engine)
	}
	// Node tags must survive the round trip, and every group member
	// must resolve to a node tag, a group, or direct — otherwise
	// sing-box starts with "dependency not found".
	valid := map[string]bool{"direct": true}
	for _, n := range back.Nodes {
		if n.Tag == "" {
			t.Errorf("node %q lost its tag in round trip", n.Name)
		}
		valid[n.Tag] = true
	}
	for _, g := range back.Groups {
		valid[g.Name] = true
	}
	for _, g := range back.Groups {
		for _, m := range g.Members {
			if !valid[m] {
				t.Errorf("group %s member %q does not resolve after round trip", g.Name, m)
			}
		}
	}
	// Port fields must survive as exact integers (json.Number), so
	// the regenerated config does not contain 443.0.
	found := false
	for _, r := range back.Rules {
		if p, ok := r["port"]; ok {
			found = true
			arr := p.([]any)
			if n, isNum := arr[0].(json.Number); !isNum || n.String() != "443" {
				t.Errorf("port after round trip = %#v, want json.Number 443", arr[0])
			}
		}
	}
	if !found {
		t.Error("DEST-PORT rule lost in round trip")
	}
	if _, err := BuildImported(back, "rule"); err != nil {
		t.Fatal(err)
	}
}
