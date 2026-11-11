package script

import (
	"net/http"
	"time"

	"sakunet/internal/surge"
)

// Cron scheduling and Surge Panel rendering (v1.2), built on the
// same one-shot VM execution as the HTTP phases:
//
//   - type=cron scripts run standalone on their cronexpr schedule
//     (no $request/$response; $notification/$persistentStore/
//     $httpClient all work). Scheduling is driven from the core
//     while the engine is up.
//   - A [Panel] entry renders by running its referenced script
//     standalone and reading title/content/icon from the script's
//     $done({...}) payload — the Surge panel contract. Results are
//     cached for the panel's update-interval; Panels() never
//     blocks on a script run (stale content is served while a
//     background refresh runs).
//
// Streaming-unlock checks and similar panel content are NOT
// built in: they arrive as user-imported scripts (config [Script]
// or module), exactly like on Surge.

// PanelView is one rendered panel for the dashboard home page.
type PanelView struct {
	Name      string `json:"name"`
	Title     string `json:"title"`
	Content   string `json:"content,omitempty"`
	Icon      string `json:"icon,omitempty"`
	IconColor string `json:"icon_color,omitempty"`
	Updated   string `json:"updated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type panelState struct {
	view       PanelView
	at         time.Time
	refreshing bool
}

const defaultPanelInterval = 3600 // seconds

// SetPanels installs the panel definitions (from the imported
// config / merged modules) and marks referenced scripts.
func (r *Runner) SetPanels(panels []surge.PanelDef) {
	r.mu.Lock()
	r.panels = panels
	r.mu.Unlock()
	for _, pd := range panels {
		for _, d := range r.defs {
			if d.Name == pd.ScriptName {
				d.PanelRef = true
			}
		}
	}
}

func (r *Runner) defByName(name string) *Def {
	for _, d := range r.defs {
		if d.Name == name {
			return d
		}
	}
	return nil
}

// runStandalone executes one script outside the HTTP pipeline
// (cron fire / panel render) and returns its raw result.
func (r *Runner) runStandalone(d *Def) *runResult {
	return r.runOne(d, &Request{Headers: http.Header{}}, nil, nil)
}

// Panels returns the current panel views, kicking off background
// refreshes for missing/stale entries. Never blocks on scripts.
func (r *Runner) Panels() []PanelView {
	r.mu.Lock()
	panels := append([]surge.PanelDef{}, r.panels...)
	r.mu.Unlock()
	out := make([]PanelView, 0, len(panels))
	now := time.Now()
	for _, pd := range panels {
		interval := pd.UpdateInterval
		if interval <= 0 {
			interval = defaultPanelInterval
		}
		r.mu.Lock()
		st := r.panelCache[pd.Name]
		stale := st == nil || now.Sub(st.at) > time.Duration(interval)*time.Second
		needRun := stale && (st == nil || !st.refreshing)
		if needRun {
			if st == nil {
				st = &panelState{view: PanelView{Name: pd.Name, Title: panelTitle(pd, nil)}}
				r.panelCache[pd.Name] = st
			}
			st.refreshing = true
		}
		var view PanelView
		if st != nil {
			view = st.view
		} else {
			view = PanelView{Name: pd.Name, Title: panelTitle(pd, nil)}
		}
		r.mu.Unlock()
		if needRun {
			go r.refreshPanel(pd)
		}
		out = append(out, view)
	}
	return out
}

func panelTitle(pd surge.PanelDef, doneRaw map[string]any) string {
	if doneRaw != nil {
		if t, ok := doneRaw["title"].(string); ok && t != "" {
			return t
		}
	}
	if pd.Title != "" {
		return pd.Title
	}
	return pd.Name
}

func (r *Runner) refreshPanel(pd surge.PanelDef) {
	view := PanelView{Name: pd.Name, Title: panelTitle(pd, nil)}
	d := r.defByName(pd.ScriptName)
	switch {
	case d == nil:
		view.Error = "面板引用的脚本「" + pd.ScriptName + "」不存在"
	case !d.Enabled || d.LoadErr != "" || d.Code == "":
		view.Error = "面板脚本不可用：" + d.LoadErr
	default:
		res := r.runStandalone(d)
		if res.doneRaw == nil {
			view.Error = "面板脚本没有返回 $done({title, content}) 内容"
		} else {
			view.Title = panelTitle(pd, res.doneRaw)
			if s, ok := res.doneRaw["content"].(string); ok {
				view.Content = s
			}
			if s, ok := res.doneRaw["icon"].(string); ok {
				view.Icon = s
			}
			if s, ok := res.doneRaw["icon-color"].(string); ok {
				view.IconColor = s
			}
		}
	}
	view.Updated = time.Now().Format("15:04:05")
	r.mu.Lock()
	st := r.panelCache[pd.Name]
	if st == nil {
		st = &panelState{}
		r.panelCache[pd.Name] = st
	}
	st.view = view
	st.at = time.Now()
	st.refreshing = false
	r.mu.Unlock()
}

// --- cron scheduler ----------------------------------------------

// StartScheduler begins firing cron scripts on their schedules.
// Idempotent; safe to call when no cron scripts exist (no-op).
func (r *Runner) StartScheduler() {
	has := false
	for _, d := range r.defs {
		if d.IsCron() {
			has = true
		}
	}
	if !has {
		return
	}
	r.mu.Lock()
	if r.schedStop != nil {
		r.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	r.schedStop = stop
	now := time.Now()
	for _, d := range r.defs {
		if d.IsCron() {
			r.lastFire[d.Name] = now
		}
	}
	r.mu.Unlock()
	go func() {
		t := time.NewTicker(r.tickDur)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				r.fireDue()
			}
		}
	}()
}

// StopScheduler halts cron firing (engine shutdown).
func (r *Runner) StopScheduler() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.schedStop != nil {
		close(r.schedStop)
		r.schedStop = nil
	}
}

func (r *Runner) fireDue() {
	now := time.Now()
	for _, d := range r.defs {
		if !d.IsCron() {
			continue
		}
		r.mu.Lock()
		last := r.lastFire[d.Name]
		r.mu.Unlock()
		if last.IsZero() {
			last = now
		}
		next := d.sched.Next(last)
		if next.IsZero() || next.After(now) {
			continue
		}
		// Fire once per tick per script; if several slots were
		// missed (machine asleep), collapse them into this run
		// and resume from now.
		r.logf(d.Name, "log", "cron 触发（"+d.CronExpr+"）")
		r.runStandalone(d)
		r.mu.Lock()
		r.lastFire[d.Name] = now
		r.mu.Unlock()
	}
}
