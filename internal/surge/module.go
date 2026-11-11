package surge

import (
	"fmt"
	"strings"
	"time"
)

// .sgmodule support. A Surge module can carry many section kinds;
// SakuNet merges the two the MITM/rewrite engine executes —
// [MITM] hostnames and [URL Rewrite] rules — into the active
// import's engine data. Script parts are counted and reported but
// NEVER executed (SakuNet has no JS script engine); [Rule] /
// [Proxy] sections of a module are reported as not merged.

type ModuleRecord struct {
	Name      string    `json:"name"`
	At        time.Time `json:"at"`
	Hostnames int       `json:"hostnames"`
	Rewrites  int       `json:"rewrites"`
	Scripts   int       `json:"scripts"`
}

// ModuleResult is the outcome of parsing one .sgmodule file.
type ModuleResult struct {
	Name         string
	Hostnames    []string
	Rewrites     []RewriteRule
	ScriptNames  []string
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
			n, _, ok := strings.Cut(line, "=")
			if ok {
				mr.ScriptNames = append(mr.ScriptNames, strings.TrimSpace(n))
			}
		default:
			if section != "" {
				mr.OtherSection[section]++
			}
		}
	}
	if len(mr.ScriptNames) > 0 {
		mr.Notes = append(mr.Notes, fmt.Sprintf("模块含 %d 个脚本：脚本部分不执行（SakuNet 无 JS 脚本引擎），重写部分已生效", len(mr.ScriptNames)))
	}
	for sec, n := range mr.OtherSection {
		mr.Notes = append(mr.Notes, fmt.Sprintf("模块 [%s] 段共 %d 行未并入（v1.0 仅并入 MITM 主机名与 URL Rewrite）", sec, n))
	}
	return mr
}

// MergeModule folds a parsed module into the import's engine data
// (deduplicated) and records the merge in the report.
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
	rec := ModuleRecord{
		Name: mr.Name, At: time.Now(),
		Hostnames: addedH, Rewrites: addedR, Scripts: len(mr.ScriptNames),
	}
	imp.Modules = append(imp.Modules, rec)
	imp.Report.Notes = append(imp.Report.Notes,
		fmt.Sprintf("模块「%s」已并入：MITM 主机名 +%d、重写规则 +%d（已生效）", mr.Name, addedH, addedR))
	imp.Report.Notes = append(imp.Report.Notes, mr.Notes...)
	return rec
}
