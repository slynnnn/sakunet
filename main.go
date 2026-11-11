// SakuNet — personal Windows proxy client.
// Go shell + sing-box sidecar; dashboard on http://127.0.0.1:18090.
//
// Usage:
//
//	sakunet                     start dashboard (core controlled from the page)
//	sakunet genconfig in.json out.json   generate sing-box config and exit
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"sakunet/internal/api"
	"sakunet/internal/config"
	"sakunet/internal/core"
	"sakunet/internal/diag"
	"sakunet/internal/elevate"
	"sakunet/internal/links"
	"sakunet/internal/surge"
	"sakunet/internal/sysproxy"
	"sakunet/internal/tray"
	"sakunet/internal/updchk"
	"sakunet/web"
)

// Version is the SakuNet release version.
const Version = "v1.0"

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "genconfig" {
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: sakunet genconfig <nodes.json> <out.json>")
			os.Exit(2)
		}
		if err := config.Generate(os.Args[2], os.Args[3], "rule"); err != nil {
			fmt.Fprintln(os.Stderr, "genconfig:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", os.Args[3])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "surge2json" {
		// Offline Surge -> sing-box converter. With only an input
		// file it prints the migration report and writes nothing
		// (handy for a private config you only want counted).
		if len(os.Args) != 3 && len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: sakunet surge2json <surge.conf> [out.json]")
			os.Exit(2)
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "surge2json:", err)
			os.Exit(1)
		}
		imp, err := surge.Parse(os.Args[2], data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "surge2json:", err)
			os.Exit(1)
		}
		// Same resolution the panel import performs, so the offline
		// build is complete (text rule-sets fetched + inlined).
		imp.Report.Notes = append(imp.Report.Notes, imp.ResolveRuleSets()...)
		// Always build in memory (validates every converted outbound
		// and rule); only write the config when an output was given.
		cfg, err := surge.BuildImported(imp, "rule")
		if err != nil {
			fmt.Fprintln(os.Stderr, "surge2json: build:", err)
			os.Exit(1)
		}
		if len(os.Args) == 4 {
			raw, _ := json.MarshalIndent(cfg, "", "  ")
			if err := os.WriteFile(os.Args[3], append(raw, '\n'), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "surge2json:", err)
				os.Exit(1)
			}
			fmt.Println("wrote", os.Args[3])
		}
		raw, _ := json.MarshalIndent(imp.Report, "", "  ")
		fmt.Println(string(raw))
		return
	}

	addr := flag.String("addr", "127.0.0.1:18090", "dashboard listen address")
	nodes := flag.String("nodes", "", "path to nodes.json (default: next to the executable)")
	flag.Parse()

	mgr, err := core.New(*nodes)
	if err != nil {
		log.Fatal(err)
	}
	clash := api.New("http://127.0.0.1:9090")

	mux := http.NewServeMux()
	index, _ := web.FS.ReadFile("index.html")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, mgr.Status())
	})
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Start(); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, mgr.Status())
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Stop(); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, mgr.Status())
	})
	mux.HandleFunc("/api/restart", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Restart(); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, mgr.Status())
	})
	mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		proxies, err := clash.Proxies(ctx)
		if err != nil {
			errJSON(w, err)
			return
		}
		type group struct {
			Name string   `json:"name"`
			Now  string   `json:"now"`
			All  []string `json:"all"`
		}
		groups := []group{}
		for name, p := range proxies {
			if p.Type == "Selector" || p.Type == "URLTest" {
				groups = append(groups, group{Name: name, Now: p.Now, All: p.All})
			}
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
		writeJSON(w, 200, groups)
	})
	mux.HandleFunc("/api/switch", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Group string `json:"group"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := clash.Switch(ctx, body.Group, body.Name); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("/api/delay", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		d, err := clash.Delay(ctx, name, "http://cp.cloudflare.com/generate_204", 10000)
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]int{"delay": d})
	})
	mux.HandleFunc("/api/delay-batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			Names []string `json:"names"`
			Group string   `json:"group"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		names := body.Names
		if body.Group != "" {
			proxies, err := clash.Proxies(ctx)
			if err != nil {
				errJSON(w, err)
				return
			}
			g, ok := proxies[body.Group]
			if !ok {
				errJSON(w, fmt.Errorf("策略组 %s 不存在", body.Group))
				return
			}
			names = g.All
		}
		filtered := names[:0]
		for _, n := range names {
			if n != "direct" {
				filtered = append(filtered, n)
			}
		}
		res := clash.BatchDelay(ctx, filtered, "http://cp.cloudflare.com/generate_204", 10000)
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		proxies, err := clash.Proxies(ctx)
		if err != nil {
			errJSON(w, err)
			return
		}
		type node struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		nodes := []node{}
		for name, p := range proxies {
			switch p.Type {
			case "Selector", "Direct", "Reject", "Compatible", "Pass", "Dns", "Fallback", "URLTest", "LoadBalance":
				continue
			}
			nodes = append(nodes, node{Name: name, Type: p.Type})
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		writeJSON(w, 200, nodes)
	})
	mux.HandleFunc("/api/connections", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		v, err := clash.Connections(ctx)
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"downloadTotal": v["downloadTotal"],
			"uploadTotal":   v["uploadTotal"],
		})
	})
	mux.HandleFunc("/api/activity", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		act, err := clash.Activity(ctx)
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, act)
	})
	mux.HandleFunc("/api/tun", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				On bool `json:"on"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				errJSON(w, err)
				return
			}
			if err := mgr.SetTun(body.On); err != nil {
				errJSON(w, err)
				return
			}
		}
		writeJSON(w, 200, map[string]any{"tun": mgr.Tun(), "admin": elevate.IsAdmin()})
	})
	mux.HandleFunc("/api/elevate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		if err := elevate.Relaunch(); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
		// Give the elevated instance a moment to come up, then exit
		// so the dashboard port and core hand over cleanly.
		go func() {
			time.Sleep(800 * time.Millisecond)
			_ = mgr.Stop()
			os.Exit(0)
		}()
	})
	mux.HandleFunc("/api/import-links", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			Text string `json:"text"`
			URL  string `json:"url"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		data := []byte(body.Text)
		if body.URL != "" {
			fetched, err := fetchSubscription(body.URL)
			if err != nil {
				errJSON(w, err)
				return
			}
			data = fetched
		}
		if len(data) == 0 {
			errJSON(w, fmt.Errorf("粘贴分享链接或填写订阅 URL"))
			return
		}
		nodes, errs := links.ParseSubscription(data)
		added := 0
		var impErr error
		if len(nodes) > 0 {
			added, impErr = mgr.ImportNodes(nodes)
		}
		errStrs := []string{}
		for _, e := range errs {
			errStrs = append(errStrs, e.Error())
		}
		if impErr != nil {
			errStrs = append(errStrs, impErr.Error())
		}
		writeJSON(w, 200, map[string]any{"parsed": len(nodes), "added": added, "errors": errStrs})
	})
	mux.HandleFunc("/api/import-module", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			errJSON(w, fmt.Errorf("缺少上传文件：%w", err))
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 4<<20))
		if err != nil {
			errJSON(w, err)
			return
		}
		mr, err := mgr.ImportModule(safeDisplayName(header.Filename), data)
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{
			"name":      mr.Name,
			"hostnames": len(mr.Hostnames),
			"rewrites":  len(mr.Rewrites),
			"scripts":   len(mr.ScriptNames),
			"notes":     mr.Notes,
		})
	})
	mux.HandleFunc("/api/selfcheck", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, diag.RunChecks(mgr, clash))
	})
	mux.HandleFunc("/api/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		bundle, _, err := diag.BuildBundle(mgr, clash, Version)
		if err != nil {
			errJSON(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=sakunet-diagnostics.zip")
		_, _ = w.Write(bundle)
	})
	mux.HandleFunc("/api/scripts/logs", func(w http.ResponseWriter, r *http.Request) {
		logs, notes := mgr.ScriptLogs()
		writeJSON(w, 200, map[string]any{"logs": logs, "notifications": notes})
	})
	mux.HandleFunc("/api/mitm/ca.cer", func(w http.ResponseWriter, r *http.Request) {
		der, err := mgr.EngineCA()
		if err != nil {
			errJSON(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=sakunet-ca.cer")
		_, _ = w.Write(der)
	})
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				errJSON(w, err)
				return
			}
			if err := mgr.SetMode(body.Mode); err != nil {
				errJSON(w, err)
				return
			}
		}
		writeJSON(w, 200, map[string]string{"mode": mgr.Mode()})
	})
	mux.HandleFunc("/api/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			errJSON(w, fmt.Errorf("缺少上传文件：%w", err))
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 16<<20))
		if err != nil {
			errJSON(w, err)
			return
		}
		rep, err := mgr.ImportSurge(safeDisplayName(header.Filename), data, r.FormValue("name"))
		if rep != nil {
			writeJSON(w, 200, rep)
			return
		}
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("/api/source", func(w http.ResponseWriter, r *http.Request) {
		st := mgr.Status()
		writeJSON(w, 200, map[string]any{
			"kind":   st.SourceKind,
			"name":   st.SourceName,
			"at":     st.SourceAt,
			"report": mgr.ImportReport(),
		})
	})
	mux.HandleFunc("/api/profiles", func(w http.ResponseWriter, r *http.Request) {
		list, err := mgr.Profiles()
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, list)
	})
	mux.HandleFunc("/api/profiles/switch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		if err := mgr.SwitchProfile(body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("/api/profiles/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		if err := mgr.DeleteProfile(body.ID); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})
	mux.HandleFunc("/api/automation", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, mgr.Automation())
	})
	mux.HandleFunc("/api/autostart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			On bool `json:"on"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		if err := mgr.SetAutostart(body.On); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, mgr.Automation())
	})
	mux.HandleFunc("/api/subscription", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errJSON(w, fmt.Errorf("POST required"))
			return
		}
		var body struct {
			URL      string `json:"url"`
			EveryH   int    `json:"every_hours"`
			Auto     bool   `json:"auto"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		if err := mgr.SetSubscription(body.URL, body.EveryH, body.Auto); err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, mgr.Automation())
	})
	mux.HandleFunc("/api/update-check", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, updchk.Latest(Version, nil))
	})
	mux.HandleFunc("/api/sysproxy", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			On bool `json:"on"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		var err error
		if body.On {
			err = sysproxy.Set(mgr.SysproxyAddr())
		} else {
			err = sysproxy.Clear()
		}
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})

	mgr.StartBackground()

	dashURL := "http://" + *addr
	log.Printf("SakuNet %s dashboard: %s", Version, dashURL)
	srv := &http.Server{Addr: *addr, Handler: mux}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	if tray.Supported() {
		cb := tray.Callbacks{
			Status: func() (bool, string) {
				st := mgr.Status()
				return st.Running, st.Mode
			},
			Start: mgr.Start,
			Stop:  mgr.Stop,
			SetMode: func(mode string) error {
				return mgr.SetMode(mode)
			},
			OpenPanel: func() { tray.OpenBrowser(dashURL) },
			Quit: func() {
				_ = mgr.Stop()
				os.Exit(0)
			},
		}
		if err := tray.Run(cb); err != nil {
			log.Printf("tray: %v", err)
			log.Fatal(<-errCh)
		}
		return
	}
	log.Fatal(<-errCh)
}

// safeDisplayName reduces an uploaded filename to its base name for
// display/storage as metadata. It is never used as a filesystem
// path, but keep it clean anyway (path traversal defence in depth).
func safeDisplayName(name string) string {
	base := name
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' || base[i] == '\\' {
			base = base[i+1:]
			break
		}
	}
	if base == "" || base == "." || base == ".." {
		return "upload.conf"
	}
	return base
}

// fetchSubscription downloads a subscription URL (http/https only,
// 4 MiB cap, 15 s timeout).
func fetchSubscription(rawURL string) ([]byte, error) {
	u, err := parseHTTPURL(rawURL)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SakuNet/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取订阅失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取订阅失败：HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func parseHTTPURL(raw string) (string, error) {
	for _, p := range []string{"https://", "http://"} {
		if len(raw) > len(p) && raw[:len(p)] == p {
			return raw, nil
		}
	}
	return "", fmt.Errorf("订阅 URL 只支持 http/https")
}
