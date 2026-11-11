package surge

import (
	"fmt"
	"strings"
	"time"
)

// .sgmodule support. A Surge module can carry many section kinds;
// SakuNet merges what its engines execute — [MITM] hostnames and
// [URL Rewrite] rules into the MITM/rewrite engine, [Script]
// definitions into the JS engine (since v1.1: http-request /
// http-response run on MITM traffic; since v1.2: cron scripts are
// scheduled and Panel-referenced scripts render panels), and
// [Panel] definitions into the panel list. [Rule] / [Proxy]
// sections of a module are reported as not merged.

type ModuleRecord struct {
	Name      string    `json:"name"`
	At        time.Time `json:"at"`
	Hostnames int       `json:"hostnames"`
	Rewrites  int       `json:"rewrites"`
	Scripts   int       `json:"scripts"`
	Panels    int       `json:"panels,omitempty"`
}

// ModuleResult is the outcome of parsing one .sgmodule file.
type ModuleResult struct {
	Name         string
	Hostnames    []string
	Rewrites     []RewriteRule
	ScriptNames  []string
	Scripts      []ScriptDef
	Panels       []PanelDef
	OtherSection map[string]int // sections present but not merged
	Notes        []string
}

// ParseModule parses .sgmodule text. It never fails wholesale:
// malformed lines are skipped, and what could not be used is
// accounted for in the result.
func ParseModule(name string, data []byte) *ModuleResult {
	text := strings.TrimPrefix(string(data), "\uFEFF")
	mr := &ModuleResult{Name: name, OtherSection: map[string]int{}}
	section := ""
	// Modules use "#!name=" style metadata and section bodies that
	// mostly mirror .conf syntax.
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(line, "#!name=") {
			mr.Name = strings.TrimSpace(strings.TrimPrefix(line, "#!name="))
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		switch section {
		case "MITM":
			// hostname = a, b   |   hostname += a, b
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(k), "+"))
			if strings.EqualFold(k, "hostname") {
				for _, h := range splitFields(v) {
					if h != "" {
						mr.Hostnames = append(mr.Hostnames, h)
					}
				}
			}
		case "URL Rewrite":
			r := RewriteRule{Raw: line}
			if f := strings.Fields(line); len(f) > 0 {
				r.Pattern = f[0]
				if len(f) > 1 {
					r.Target = f[1]
				}
				if len(f) > 2 {
					r.Kind = f[2]
				}
			}
			mr.Rewrites = append(mr.Rewrites, r)
		case "Script":
			n, rest, ok := strings.Cut(line, "=")
			if ok {
				name := strings.TrimSpace(n)
				mr.ScriptNames = append(mr.ScriptNames, name)
				_, kv := params(splitFields(rest))
				mr.Scripts = append(mr.Scripts, ScriptDef{Name: name, Params: kv})
			}
		case "Panel":
			n, rest, ok := strings.Cut(line, "=")
			if ok {
				_, kv := params(splitFields(rest))
				pd := PanelDef{
					Name:       strings.TrimSpace(n),
					ScriptName: kv["script-name"],
					Title:      kv["title"],
				}
				if v := kv["update-interval"]; v != "" {
					pd.UpdateInterval = atoi(v, 0)
				}
				mr.Panels = append(mr.Panels, pd)
			}
		default:
			if section != "" {
				mr.OtherSection[section]++
			}
		}
	}
	if len(mr.ScriptNames) > 0 {
		mr.Notes = append(mr.Notes, fmt.Sprintf("模块含 %d 个脚本：定义已并入 JS 脚本引擎（http-request/http-response 执行，其余类型暂不支持），源码在导入时解析", len(mr.ScriptNames)))
	}
	for sec, n := range mr.OtherSection {
		mr.Notes = append(mr.Notes, fmt.Sprintf("模块 [%s] 段共 %d 行未并入（仅并入 MITM 主机名、URL Rewrite 与 Script 定义）", sec, n))
	}
	return mr
}

// MergeModule folds a parsed module into the import's engine data
// (deduplicated) and records the merge in the report. Script
// definitions are merged too (tagged with the module as their
// source); their bodies are resolved by ResolveScripts afterwards.
func (imp *Imported) MergeModule(mr *ModuleResult) ModuleRecord {
	have := map[string]bool{}
	for _, h := range imp.Engine.MITMHostnames {
		have[h] = true
	}
	addedH := 0
	for _, h := range mr.Hostnames {
		if !have[h] {
			have[h] = true
			imp.Engine.MITMHostnames = append(imp.Engine.MITMHostnames, h)
			addedH++
		}
	}
	haveR := map[string]bool{}
	for _, r := range imp.Engine.URLRewrites {
		haveR[r.Raw] = true
	}
	addedR := 0
	for _, r := range mr.Rewrites {
		if !haveR[r.Raw] {
			haveR[r.Raw] = true
			imp.Engine.URLRewrites = append(imp.Engine.URLRewrites, r)
			addedR++
		}
	}
	haveS := map[string]bool{}
	scriptKey := func(sd ScriptDef) string {
		return sd.Name + "|" + sd.Params["type"] + "|" + sd.Params["pattern"] + "|" + sd.Params["script-path"]
	}
	for _, sd := range imp.Engine.Scripts {
		haveS[scriptKey(sd)] = true
	}
	addedS := 0
	for _, sd := range mr.Scripts {
		if haveS[scriptKey(sd)] {
			continue
		}
		haveS[scriptKey(sd)] = true
		// Pre-tag the display source so resolution (resolve.go)
		// keeps the module attribution instead of the bare path.
		sd.Resolved = &ResolvedScript{Source: "模块「" + mr.Name + "」", Enabled: true}
		imp.Engine.Scripts = append(imp.Engine.Scripts, sd)
		addedS++
	}
	haveP := map[string]bool{}
	for _, p := range imp.Engine.Panels {
		haveP[p.Name] = true
	}
	addedP := 0
	for _, pd := range mr.Panels {
		if haveP[pd.Name] {
			continue
		}
		haveP[pd.Name] = true
		imp.Engine.Panels = append(imp.Engine.Panels, pd)
		addedP++
	}
	rec := ModuleRecord{
		Name: mr.Name, At: time.Now(),
		Hostnames: addedH, Rewrites: addedR, Scripts: len(mr.ScriptNames), Panels: addedP,
	}
	imp.Modules = append(imp.Modules, rec)
	imp.Report.Notes = append(imp.Report.Notes,
		fmt.Sprintf("模块「%s」已并入：MITM 主机名 +%d、重写规则 +%d、脚本定义 +%d、面板 +%d（已生效）", mr.Name, addedH, addedR, addedS, addedP))
	imp.Report.Notes = append(imp.Report.Notes, mr.Notes...)
	return rec
}
