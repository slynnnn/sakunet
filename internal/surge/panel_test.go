package surge

import (
	"testing"
)

const panelConf = `[Proxy]
A = snell, 192.0.2.1, 8000, psk=secret, version=5

[Proxy Group]
Main = select, A, DIRECT

[Script]
信息脚本 = type=generic, script-path=https://example.com/panel.js

[Panel]
信息 = script-name=信息脚本, title=账号信息, update-interval=7200

[Rule]
FINAL,Main
`

func TestParsePanelSection(t *testing.T) {
	imp, err := Parse("panel.conf", []byte(panelConf))
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Engine.Panels) != 1 {
		t.Fatalf("panels = %+v", imp.Engine.Panels)
	}
	pd := imp.Engine.Panels[0]
	if pd.Name != "信息" || pd.ScriptName != "信息脚本" || pd.Title != "账号信息" || pd.UpdateInterval != 7200 {
		t.Errorf("panel def = %+v", pd)
	}
	found := false
	for _, ps := range imp.Report.EnginePending {
		if ps.Section == "Panel" && ps.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("report pending = %+v", imp.Report.EnginePending)
	}
}

func TestModulePanelMerge(t *testing.T) {
	mod := "#!name=面板模块\n" +
		"[Script]\n" +
		"状态脚本 = type=generic, script-path=https://example.com/s.js\n" +
		"[Panel]\n" +
		"状态 = script-name=状态脚本, title=状态\n"
	mr := ParseModule("panel.sgmodule", []byte(mod))
	if len(mr.Panels) != 1 || mr.Panels[0].ScriptName != "状态脚本" {
		t.Fatalf("module panels = %+v", mr.Panels)
	}
	imp, err := Parse("panel.conf", []byte(panelConf))
	if err != nil {
		t.Fatal(err)
	}
	rec := imp.MergeModule(mr)
	if rec.Panels != 1 || len(imp.Engine.Panels) != 2 {
		t.Errorf("after merge: rec=%+v panels=%+v", rec, imp.Engine.Panels)
	}
	// Same module again: no duplicate panel.
	rec = imp.MergeModule(mr)
	if rec.Panels != 0 || len(imp.Engine.Panels) != 2 {
		t.Errorf("re-merge duplicated: rec=%+v panels=%d", rec, len(imp.Engine.Panels))
	}
}
