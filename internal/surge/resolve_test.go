package surge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ResolveScripts: a remote script-path is downloaded, cached and
// fingerprinted at import; a dead URL and a local path each fail
// into their own readable note, never silently.
func TestResolveScripts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.js" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "// ad filter\n$done({});")
	}))
	defer srv.Close()

	imp := &Imported{}
	imp.Engine.Scripts = []ScriptDef{
		{Name: "remote-ok", Params: map[string]string{
			"type": "http-response", "pattern": "ads", "script-path": srv.URL + "/filter.js",
			"requires-body": "true", "timeout": "5",
		}},
		{Name: "remote-dead", Params: map[string]string{
			"type": "http-request", "script-path": srv.URL + "/missing.js",
		}},
		{Name: "local-missing", Params: map[string]string{
			"type": "http-request", "script-path": "scripts/nope.js",
		}},
	}
	// remote-dead points at a live server but a 404 path.
	notes := imp.ResolveScripts()

	ok := imp.Engine.Scripts[0].Resolved
	if ok == nil || ok.LoadError != "" {
		t.Fatalf("remote-ok resolved = %+v", ok)
	}
	if !strings.Contains(ok.Code, "ad filter") || ok.SHA256 == "" {
		t.Fatalf("remote-ok code/sha = %q / %q", ok.Code, ok.SHA256)
	}
	if !ok.RequiresBody || ok.TimeoutSec != 5 {
		t.Fatalf("remote-ok params = %+v", ok)
	}
	dead := imp.Engine.Scripts[1].Resolved
	if dead == nil || !strings.Contains(dead.LoadError, "404") {
		t.Fatalf("remote-dead = %+v", dead)
	}
	local := imp.Engine.Scripts[2].Resolved
	if local == nil || !strings.Contains(local.LoadError, "本地脚本文件读取失败") {
		t.Fatalf("local-missing = %+v", local)
	}
	if len(notes) != 2 {
		t.Fatalf("notes = %v, want 2 failure notes", notes)
	}
}

// Module scripts merge into the import's engine data and resolve
// with the module kept as their display source.
func TestModuleScriptsMergeAndResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "$done({});")
	}))
	defer srv.Close()

	mod := "#!name=去广告模块\n" +
		"[Script]\n" +
		"去广告 = type=http-response, pattern=ads, script-path=" + srv.URL + "/a.js\n" +
		"[MITM]\n" +
		"hostname = ads.example.com\n"
	mr := ParseModule("ad.sgmodule", []byte(mod))
	if len(mr.Scripts) != 1 || len(mr.ScriptNames) != 1 {
		t.Fatalf("module scripts = %d/%d", len(mr.Scripts), len(mr.ScriptNames))
	}
	imp := &Imported{}
	imp.MergeModule(mr)
	if len(imp.Engine.Scripts) != 1 {
		t.Fatalf("merged scripts = %d", len(imp.Engine.Scripts))
	}
	notes := imp.ResolveScripts()
	if len(notes) != 0 {
		t.Fatalf("resolve notes = %v", notes)
	}
	r := imp.Engine.Scripts[0].Resolved
	if r == nil || r.Code == "" || !strings.Contains(r.Source, "去广告模块") {
		t.Fatalf("resolved = %+v", r)
	}
	// Merging the same module again must not duplicate the script.
	imp.MergeModule(mr)
	if len(imp.Engine.Scripts) != 1 {
		t.Fatalf("after re-merge scripts = %d", len(imp.Engine.Scripts))
	}
}
