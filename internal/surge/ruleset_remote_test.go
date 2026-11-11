package surge

import (
	"errors"
	"strings"
	"testing"
)

const remoteSetConf = `[Proxy]
A = snell, 192.0.2.1, 8000, psk=secret, version=5

[Proxy Group]
Main = select, A, DIRECT

[Rule]
RULE-SET,https://cdn.example.com/sets/block.srs,Main
RULE-SET,https://cdn.example.com/sets/direct.json,DIRECT
RULE-SET,https://lists.example.com/plain.list,Main
DOMAIN-SET,https://lists.example.com/domains.txt,DIRECT
GEOIP,CN,DIRECT
GEOIP,cn,Main
FINAL,Main
`

func findSetDef(imp *Imported, tag string) map[string]any {
	for _, rs := range imp.ExtraRuleSets {
		if rs["tag"] == tag {
			return rs
		}
	}
	return nil
}

func TestRemoteRuleSetFormats(t *testing.T) {
	imp, err := Parse("remote.conf", []byte(remoteSetConf))
	if err != nil {
		t.Fatal(err)
	}
	rep := imp.Report
	if len(rep.Unmigrated) != 0 {
		t.Fatalf("unmigrated = %v, want none", rep.Unmigrated)
	}
	// .srs -> remote binary
	var srsDef map[string]any
	for _, rs := range imp.ExtraRuleSets {
		if rs["format"] == "binary" && strings.HasSuffix(rs["url"].(string), ".srs") &&
			!strings.Contains(rs["url"].(string), "sing-geoip") {
			srsDef = rs
		}
	}
	if srsDef == nil || srsDef["type"] != "remote" || srsDef["update_interval"] != "24h" {
		t.Errorf("srs def = %v", srsDef)
	}
	// .json -> remote source
	var jsonDef map[string]any
	for _, rs := range imp.ExtraRuleSets {
		if u, ok := rs["url"].(string); ok && strings.HasSuffix(u, ".json") {
			jsonDef = rs
		}
	}
	if jsonDef == nil || jsonDef["format"] != "source" || jsonDef["type"] != "remote" {
		t.Errorf("json def = %v", jsonDef)
	}
	// GEOIP (both cases) -> one shared geoip-cn remote binary def.
	geo := findSetDef(imp, "geoip-cn")
	if geo == nil || geo["format"] != "binary" ||
		geo["url"] != "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" {
		t.Errorf("geoip def = %v", geo)
	}
	geoCount := 0
	for _, rs := range imp.ExtraRuleSets {
		if rs["tag"] == "geoip-cn" {
			geoCount++
		}
	}
	if geoCount != 1 {
		t.Errorf("geoip-cn defs = %d, want 1 (deduped)", geoCount)
	}
	// Two text references pending.
	if len(imp.PendingTextSets) != 2 {
		t.Fatalf("pending text sets = %d, want 2", len(imp.PendingTextSets))
	}
}

func TestResolveRuleSetsSuccess(t *testing.T) {
	orig := fetchTextSet
	defer func() { fetchTextSet = orig }()
	fetchTextSet = func(url string) ([]byte, error) {
		if strings.Contains(url, "plain.list") {
			return []byte("# comment\nDOMAIN,ads.example.com\nDOMAIN-SUFFIX,tracker.net\nIP-CIDR,203.0.113.0/24\nUSER-AGENT,Foo*\n"), nil
		}
		return []byte("bare-one.com\n.bare-two.com\nDOMAIN-KEYWORD,telemetry\n"), nil
	}
	imp, err := Parse("remote.conf", []byte(remoteSetConf))
	if err != nil {
		t.Fatal(err)
	}
	notes := imp.ResolveRuleSets()
	if len(imp.PendingTextSets) != 0 {
		t.Fatalf("pending left = %v", imp.PendingTextSets)
	}
	if len(notes) != 2 {
		t.Errorf("notes = %v, want 2", notes)
	}
	// Both tags now have inline definitions.
	for _, ref := range []string{"rs-plain-", "rs-domains-"} {
		found := false
		for _, rs := range imp.ExtraRuleSets {
			if tag, _ := rs["tag"].(string); strings.HasPrefix(tag, ref) && rs["type"] == "inline" {
				found = true
				rules := rs["rules"].([]any)
				if len(rules) == 0 {
					t.Errorf("inline set %s has no rules", tag)
				}
			}
		}
		if !found {
			t.Errorf("no inline def with prefix %s", ref)
		}
	}
	if len(imp.Report.Unmigrated) != 0 {
		t.Errorf("unmigrated = %v, want none", imp.Report.Unmigrated)
	}
}

func TestResolveRuleSetsFailureDropsRules(t *testing.T) {
	orig := fetchTextSet
	defer func() { fetchTextSet = orig }()
	fetchTextSet = func(url string) ([]byte, error) {
		return nil, errors.New("connection refused")
	}
	imp, err := Parse("remote.conf", []byte(remoteSetConf))
	if err != nil {
		t.Fatal(err)
	}
	before := imp.Report.RulesOK
	imp.ResolveRuleSets()
	// Two text references failed -> two rules dropped, two
	// unmigrated entries, counts consistent.
	if got := before - imp.Report.RulesOK; got != 2 {
		t.Errorf("rules dropped = %d, want 2 (ok %d -> %d)", got, before, imp.Report.RulesOK)
	}
	if len(imp.Report.Unmigrated) != 2 {
		t.Errorf("unmigrated = %v, want 2", imp.Report.Unmigrated)
	}
	// No rule may reference a tag with no definition left.
	defined := map[string]bool{}
	for _, rs := range imp.ExtraRuleSets {
		defined[rs["tag"].(string)] = true
	}
	for _, r := range imp.Rules {
		if tags, ok := r["rule_set"].([]string); ok {
			for _, tag := range tags {
				if !defined[tag] {
					t.Errorf("rule references undefined set %q", tag)
				}
			}
		}
	}
}

func TestConvertTextSet(t *testing.T) {
	def, st, err := convertTextSet("rs-x", []byte(
		"DOMAIN,a.com\nDOMAIN-SUFFIX,b.com\nDOMAIN-KEYWORD,ads\nIP-CIDR,10.0.0.0/8\nIP-CIDR6,fd00::/8\nbare.org\nHOST-WILDCARD,*.x.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if st.domain != 1 || st.suffix != 2 || st.keyword != 1 || st.ipcidr != 2 || st.skipped != 1 {
		t.Errorf("stats = %+v", st)
	}
	if def["type"] != "inline" || def["tag"] != "rs-x" {
		t.Errorf("def = %v", def)
	}
	if _, _, err := convertTextSet("rs-y", []byte("# nothing here\n")); err == nil {
		t.Error("empty list should error")
	}
}
