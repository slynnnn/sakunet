// Package surge parses a Surge .conf file and migrates its [Proxy],
// [Proxy Group] and [Rule] sections into SakuNet's internal model
// (config.Node list, selector/urltest groups and sing-box route
// rules). Anything that has no faithful sing-box equivalent is not
// dropped silently: it lands in Report.Unmigrated with a reason, and
// the dashboard shows that list to the user after import.
//
// The import runs entirely locally; nothing is uploaded anywhere.
package surge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sakunet/internal/config"
)

// Unmigrated is one source line (or fragment) that was not converted.
// Desc never contains credentials: proxies are described by name and
// type only, rules by type and target policy only.
type Unmigrated struct {
	Section string `json:"section"` // Proxy | Proxy Group | Rule
	Desc    string `json:"desc"`
	Reason  string `json:"reason"`
}

// PendingSection is one engine-backed section ([MITM],
// [URL Rewrite], [Script]) that was fully parsed and preserved on
// import. Since v1.0 the MITM/rewrite engine executes the first
// two; since v1.1 the JS engine executes http-request /
// http-response scripts too (other script types stay preserved
// and are reported as unsupported). It is NOT an unmigrated item:
// nothing is lost.
type PendingSection struct {
	Section string `json:"section"` // MITM | URL Rewrite | Script
	Count   int    `json:"count"`
	Summary string `json:"summary"`
}

// Report summarises one import run for the result page.
type Report struct {
	SourceName    string           `json:"source_name"`
	NodesOK       int              `json:"nodes_ok"`
	NodesSkipped  int              `json:"nodes_skipped"`
	GroupsOK      int              `json:"groups_ok"`
	RulesOK       int              `json:"rules_ok"`
	RulesDeduped  int              `json:"rules_deduped"` // legacy field, always 0 (no built-in routing to dedupe against)
	Unmigrated    []Unmigrated     `json:"unmigrated"`
	EnginePending []PendingSection `json:"engine_pending,omitempty"` // parsed & preserved, engine lands in v0.4
	Notes         []string         `json:"notes,omitempty"`          // approximations applied
	FinalPolicy   string           `json:"final_policy,omitempty"`
	IgnoredParams []string         `json:"ignored_params,omitempty"` // "type.key ×N" with no sing-box equivalent
}

// GroupDef is one migrated [Proxy Group] entry.
type GroupDef struct {
	Name      string   `json:"name"` // outbound tag
	Kind      string   `json:"kind"` // selector | urltest
	Members   []string `json:"members"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
}

// PanelDef is one [Panel] entry: a named panel rendered by
// running the referenced script and showing its $done payload
// (title/content/icon). UpdateInterval is the refresh cadence in
// seconds (0 = engine default).
type PanelDef struct {
	Name           string `json:"name"`
	ScriptName     string `json:"script_name"`
	Title          string `json:"title,omitempty"`
	UpdateInterval int    `json:"update_interval,omitempty"`
}

// EngineData preserves the engine-backed sections: nothing from
// the user's config is thrown away, even though the
// MITM/rewrite/script engine itself ships in v0.4.
type EngineData struct {
	MITMHostnames []string          `json:"mitm_hostnames,omitempty"`
	MITMParams    map[string]string `json:"mitm_params,omitempty"` // ca-p12/passphrase etc., stored locally only
	URLRewrites   []RewriteRule     `json:"url_rewrites,omitempty"`
	Scripts       []ScriptDef       `json:"scripts,omitempty"`
	Panels        []PanelDef        `json:"panels,omitempty"`
}

// RewriteRule is one [URL Rewrite] line: pattern, replacement and
// kind (302/307/header/...), plus the raw line for fidelity.
type RewriteRule struct {
	Pattern string `json:"pattern"`
	Target  string `json:"target,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Raw     string `json:"raw"`
}

// ScriptDef is one [Script] entry (name + its key=value params).
type ScriptDef struct {
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
	// Resolved is filled in at panel import time (see resolve.go):
	// the script body is fetched/read and fingerprinted so the JS
	// engine can run it without touching the network per request.
	// It stays nil for offline/report-only parses.
	Resolved *ResolvedScript `json:"resolved,omitempty"`
}

// ResolvedScript is a script definition after source resolution.
type ResolvedScript struct {
	Type         string `json:"type"`
	Pattern      string `json:"pattern,omitempty"`
	Source       string `json:"source"` // 配置来源描述：Surge 配置 / 模块名 / script-path 原文
	Code         string `json:"code,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	TimeoutSec   int    `json:"timeout_sec,omitempty"`
	RequiresBody bool   `json:"requires_body,omitempty"`
	CronExpr     string `json:"cronexpr,omitempty"` // type=cron only
	Enabled      bool   `json:"enabled"`
	LoadError    string `json:"load_error,omitempty"`
}

// Imported is the persisted result of a Surge import (imported.json).
// Rules and ExtraRuleSets are raw sing-box JSON fragments; they are
// decoded with json.Number semantics on load (see LoadImported) so
// integer fields survive the round trip.
// TextSetRef is one RULE-SET / DOMAIN-SET reference whose URL
// serves a plain-text list (Surge/Clash classical format). sing-box
// cannot consume that format remotely, so the list is fetched and
// converted to an inline rule-set at import time (see
// resolve_rulesets.go). Desc is the credential-free report label.
type TextSetRef struct {
	Tag  string `json:"tag"`
	URL  string `json:"url"`
	Desc string `json:"desc"`
}

type Imported struct {
	SourceName    string           `json:"source_name"`
	ImportedAt    time.Time        `json:"imported_at"`
	Nodes         []config.Node    `json:"nodes"`
	Groups        []GroupDef       `json:"groups"`
	Rules         []map[string]any `json:"rules"`
	ExtraRuleSets []map[string]any `json:"extra_rule_sets,omitempty"`
	// PendingTextSets holds text-format rule-set references that
	// still need fetch+convert (ResolveRuleSets). Empty once
	// resolved; leftovers mean resolution never ran (offline parse).
	PendingTextSets []TextSetRef `json:"pending_text_sets,omitempty"`
	Final         string           `json:"final,omitempty"`
	Engine        EngineData       `json:"engine"`
	Modules       []ModuleRecord   `json:"modules,omitempty"`
	Report        Report           `json:"report"`
}

// rawConfig is the section-level parse of the .conf text.
type rawConfig struct {
	proxies  []rawLine
	groups   []rawLine
	rules    []string
	mitm     []string
	rewrites []string
	scripts  []rawLine
	panels   []rawLine
}

// rawLine is one "Name = rest" entry of [Proxy] / [Proxy Group].
type rawLine struct {
	name   string
	fields []string // comma-split of rest, bracket/quote aware
}

func splitFields(s string) []string {
	var out []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

// parseSections splits the file into the sections we migrate. Other
// sections ([General], [MITM], [URL Rewrite], ...) have no sing-box
// client-side equivalent here and are ignored by design.
func parseSections(text string) *rawConfig {
	rc := &rawConfig{}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		switch section {
		case "Proxy", "Proxy Group", "Script", "Panel":
			name, rest, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			rl := rawLine{name: strings.TrimSpace(name), fields: splitFields(rest)}
			switch section {
			case "Proxy":
				rc.proxies = append(rc.proxies, rl)
			case "Proxy Group":
				rc.groups = append(rc.groups, rl)
			case "Script":
				rc.scripts = append(rc.scripts, rl)
			case "Panel":
				rc.panels = append(rc.panels, rl)
			}
		case "Rule":
			rc.rules = append(rc.rules, line)
		case "MITM":
			rc.mitm = append(rc.mitm, line)
		case "URL Rewrite":
			rc.rewrites = append(rc.rewrites, line)
		}
	}
	return rc
}

// params splits fields into bare positional tokens and key=value
// parameters (keys lower-cased).
func params(fields []string) (pos []string, kv map[string]string) {
	kv = map[string]string{}
	for _, f := range fields {
		if k, v, ok := strings.Cut(f, "="); ok && isParamKey(k) {
			kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		} else {
			pos = append(pos, f)
		}
	}
	return pos, kv
}

var paramKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

func isParamKey(k string) bool {
	k = strings.TrimSpace(k)
	// A member name containing '=' is not expected in Surge configs;
	// keys are plain identifiers.
	return paramKeyRe.MatchString(k)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// Parse parses Surge config text into an Imported model plus its
// migration Report. It never fails wholesale: individual bad lines
// are counted and listed in the report instead.
func Parse(sourceName string, data []byte) (*Imported, error) {
	text := strings.TrimPrefix(string(data), "\uFEFF")
	rc := parseSections(text)
	imp := &Imported{SourceName: sourceName, ImportedAt: time.Now()}
	rep := &imp.Report
	rep.SourceName = sourceName
	ignored := map[string]int{}
	noteIgnored := func(typ, key string) { ignored[typ+"."+key]++ }

	// ---------- [Proxy] ----------
	nodeByName := map[string]*config.Node{}
	seenTag := map[string]int{}
	for _, pl := range rc.proxies {
		node, reason := convertProxy(pl, noteIgnored)
		if node == nil {
			rep.NodesSkipped++
			rep.Unmigrated = append(rep.Unmigrated, Unmigrated{
				Section: "Proxy",
				Desc:    fmt.Sprintf("%s（%s）", pl.name, proxyTypeOf(pl)),
				Reason:  reason,
			})
			continue
		}
		tag := node.Name
		seenTag[tag]++
		if seenTag[tag] > 1 {
			tag = fmt.Sprintf("%s-%d", tag, seenTag[tag])
		}
		node.Tag = tag
		imp.Nodes = append(imp.Nodes, *node)
		nodeByName[pl.name] = node
		rep.NodesOK++
	}
	nodeTags := make([]string, 0, len(imp.Nodes))
	for i := range imp.Nodes {
		nodeTags = append(nodeTags, imp.Nodes[i].Tag)
	}

	// ---------- [Proxy Group] ----------
	groupNames := map[string]bool{}
	for _, gl := range rc.groups {
		groupNames[gl.name] = true
	}
	for _, gl := range rc.groups {
		gd, reason, notes := convertGroup(gl, nodeByName, nodeTags, groupNames)
		if gd == nil {
			rep.Unmigrated = append(rep.Unmigrated, Unmigrated{
				Section: "Proxy Group", Desc: gl.name, Reason: reason,
			})
			continue
		}
		imp.Groups = append(imp.Groups, *gd)
		rep.GroupsOK++
		rep.Notes = append(rep.Notes, notes...)
	}

	// Break group reference cycles (A includes B, B includes A, or
	// a group that includes itself): sing-box refuses cyclic
	// outbound dependencies, so a hostile or sloppy config would
	// otherwise turn into a core that cannot start. Each removed
	// back-edge is noted in the report.
	breakGroupCycles(imp, rep)

	// Policy resolution set: only what the imported config itself
	// defines (nodes + groups) plus DIRECT. SakuNet adds no groups
	// of its own when an imported config is active.
	policies := map[string]string{"DIRECT": "direct"}
	for name, n := range nodeByName {
		policies[name] = n.Tag
	}
	for _, g := range imp.Groups {
		policies[g.Name] = g.Name
	}
	resolvePolicy := func(p string) (string, bool) {
		if p == "REJECT" || p == "REJECT-DROP" || p == "REJECT-TINYGIF" {
			return "", true // handled as reject action by caller via isReject
		}
		t, ok := policies[p]
		return t, ok
	}
	isReject := func(p string) bool {
		return p == "REJECT" || p == "REJECT-DROP" || p == "REJECT-TINYGIF"
	}

	// ---------- [Rule] ----------
	conv := &ruleConverter{
		imp: imp, rep: rep,
		resolve: resolvePolicy, isReject: isReject,
		extraSets: map[string]string{},
		textSets:  map[string]string{},
		geoSets:   map[string]bool{},
	}
	for _, rl := range rc.rules {
		conv.convert(rl)
	}
	imp.Final = conv.finalTag
	rep.FinalPolicy = conv.finalPol

	// ---------- Engine-backed sections: parse & preserve ----------
	convertEngineSections(rc, imp)

	// Ignored parameter summary, deterministic order.
	keys := make([]string, 0, len(ignored))
	for k := range ignored {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		rep.IgnoredParams = append(rep.IgnoredParams, fmt.Sprintf("%s ×%d", k, ignored[k]))
	}
	if rep.Unmigrated == nil {
		rep.Unmigrated = []Unmigrated{}
	}
	return imp, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func proxyTypeOf(pl rawLine) string {
	if len(pl.fields) == 0 {
		return "?"
	}
	return strings.ToLower(pl.fields[0])
}
