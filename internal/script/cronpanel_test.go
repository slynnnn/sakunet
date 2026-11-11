package script

import (
	"strings"
	"testing"
	"time"

	"sakunet/internal/surge"
)

func mkResolved(name, typ, cronExpr, code string) surge.ScriptDef {
	return surge.ScriptDef{
		Name:   name,
		Params: map[string]string{"type": typ},
		Resolved: &surge.ResolvedScript{
			Type: typ, Code: code, CronExpr: cronExpr, Enabled: true,
			TimeoutSec: 5, Source: "test",
		},
	}
}

func TestCronDefValidation(t *testing.T) {
	ed := &surge.EngineData{Scripts: []surge.ScriptDef{
		mkResolved("ok", "cron", "0 9 * * *", "$done({});"),
		mkResolved("bad-expr", "cron", "99 * * * *", "$done({});"),
		mkResolved("no-expr", "cron", "", "$done({});"),
	}}
	defs := FromEngine(ed)
	if !defs[0].IsCron() {
		t.Error("valid cron def must be runnable")
	}
	if defs[1].IsCron() || defs[1].LoadErr == "" {
		t.Errorf("bad expr def = %+v", defs[1])
	}
	if defs[2].IsCron() || !strings.Contains(defs[2].LoadErr, "cronexpr") {
		t.Errorf("missing expr def = %+v", defs[2])
	}
}

func TestCronSchedulerFires(t *testing.T) {
	ed := &surge.EngineData{Scripts: []surge.ScriptDef{
		mkResolved("tick", "cron", "* * * * *",
			`$persistentStore.write(String(Number($persistentStore.read("fires") || "0") + 1), "fires"); $done({});`),
	}}
	r := NewRunner(FromEngine(ed), Options{})
	r.StartScheduler()
	defer r.StopScheduler()
	// Backdate the last fire so the * * * * * schedule is due,
	// then drive the same fireDue the ticker calls.
	r.mu.Lock()
	r.lastFire["tick"] = time.Now().Add(-2 * time.Minute)
	r.mu.Unlock()
	r.fireDue()
	if v, ok := r.storeRead("fires"); !ok || v != "1" {
		t.Fatalf("cron script did not fire (store=%q,%v); infos=%+v", v, ok, r.Infos())
	}
	infos := r.Infos()
	if len(infos) != 1 || !infos[0].LastOK || infos[0].Cron != "* * * * *" {
		t.Fatalf("infos = %+v", infos)
	}
	// Not due again immediately: a second fireDue is a no-op.
	r.fireDue()
	if v, _ := r.storeRead("fires"); v != "1" {
		t.Fatalf("cron fired twice for one slot: %q", v)
	}
}

func TestPanelRendering(t *testing.T) {
	ed := &surge.EngineData{
		Scripts: []surge.ScriptDef{
			mkResolved("infoPanel", "generic", "",
				`$done({title: "信息面板", content: "第一行\n第二行", icon: "info", "icon-color": "#f00"});`),
			mkResolved("brokenPanel", "generic", "",
				`throw new Error("boom");`),
		},
		Panels: []surge.PanelDef{
			{Name: "信息", ScriptName: "infoPanel", UpdateInterval: 3600},
			{Name: "坏面板", ScriptName: "brokenPanel"},
			{Name: "缺脚本", ScriptName: "ghost"},
		},
	}
	r := NewRunner(FromEngine(ed), Options{})
	r.SetPanels(ed.Panels)
	// First call kicks background refreshes; poll for content.
	deadline := time.Now().Add(5 * time.Second)
	var views []PanelView
	for time.Now().Before(deadline) {
		views = r.Panels()
		if len(views) == 3 && views[0].Content != "" && views[1].Error != "" && views[2].Error != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(views) != 3 {
		t.Fatalf("views = %d", len(views))
	}
	if views[0].Title != "信息面板" || !strings.Contains(views[0].Content, "第二行") || views[0].Icon != "info" || views[0].IconColor != "#f00" {
		t.Errorf("panel 0 = %+v", views[0])
	}
	if views[1].Error == "" {
		t.Errorf("throwing panel script must surface an error view: %+v", views[1])
	}
	if !strings.Contains(views[2].Error, "不存在") {
		t.Errorf("missing script panel error = %+v", views[2])
	}
	// Infos mark panel-referenced scripts as supported.
	found := false
	for _, in := range r.Infos() {
		if in.Name == "infoPanel" && in.Panel && in.Supported {
			found = true
		}
	}
	if !found {
		t.Errorf("infos = %+v", r.Infos())
	}
}
