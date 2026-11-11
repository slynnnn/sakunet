package surge

import (
	"fmt"
	"strings"
)

// convertEngineSections parses [MITM], [URL Rewrite] and [Script]
// into imp.Engine and records them in the report as engine-backed
// sections: preserved in full and (since v1.0) executed by the
// MITM/rewrite engine — MITM and URL Rewrite live, Script stored
// but never executed (no JS engine). They deliberately do not
// appear in Report.Unmigrated: nothing about them is lost.
func convertEngineSections(rc *rawConfig, imp *Imported) {
	rep := &imp.Report

	// [MITM]: key = value lines. `hostname` carries a comma list;
	// everything else (ca-p12, ca-passphrase, ...) is kept as-is.
	if len(rc.mitm) > 0 {
		imp.Engine.MITMParams = map[string]string{}
		for _, line := range rc.mitm {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)
			if k == "hostname" {
				for _, h := range splitFields(v) {
					if h != "" {
						imp.Engine.MITMHostnames = append(imp.Engine.MITMHostnames, h)
					}
				}
				continue
			}
			imp.Engine.MITMParams[k] = v
		}
		rep.EnginePending = append(rep.EnginePending, PendingSection{
			Section: "MITM",
			Count:   len(imp.Engine.MITMHostnames),
			Summary: fmt.Sprintf("hostname %d 条，参数 %d 项已保存", len(imp.Engine.MITMHostnames), len(imp.Engine.MITMParams)),
		})
	}

	// [URL Rewrite]: whitespace-separated "pattern target kind".
	for _, line := range rc.rewrites {
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
		imp.Engine.URLRewrites = append(imp.Engine.URLRewrites, r)
	}
	if len(imp.Engine.URLRewrites) > 0 {
		rep.EnginePending = append(rep.EnginePending, PendingSection{
			Section: "URL Rewrite",
			Count:   len(imp.Engine.URLRewrites),
			Summary: fmt.Sprintf("%d 条重写规则已保存", len(imp.Engine.URLRewrites)),
		})
	}

	// [Script]: name = type=..., pattern=..., script-path=..., ...
	for _, sl := range rc.scripts {
		_, kv := params(sl.fields)
		imp.Engine.Scripts = append(imp.Engine.Scripts, ScriptDef{Name: sl.name, Params: kv})
	}
	if len(imp.Engine.Scripts) > 0 {
		rep.EnginePending = append(rep.EnginePending, PendingSection{
			Section: "Script",
			Count:   len(imp.Engine.Scripts),
			Summary: fmt.Sprintf("%d 个脚本定义已保存", len(imp.Engine.Scripts)),
		})
	}
}
