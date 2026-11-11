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
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"sakunet/internal/api"
	"sakunet/internal/config"
	"sakunet/internal/core"
	"sakunet/internal/sysproxy"
	"sakunet/web"
)

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
			if p.Type == "Selector" {
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
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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
	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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
	mux.HandleFunc("/api/sysproxy", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			On bool `json:"on"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			errJSON(w, err)
			return
		}
		var err error
		if body.On {
			err = sysproxy.Set("127.0.0.1:2080")
		} else {
			err = sysproxy.Clear()
		}
		if err != nil {
			errJSON(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"ok": "1"})
	})

	log.Printf("SakuNet dashboard: http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
