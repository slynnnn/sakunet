package script

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sakunet/internal/surge"
)

func def(name, typ, code string) *Def {
	return &Def{Name: name, Type: typ, Enabled: true, Supported: true, Code: code, Timeout: 2 * time.Second}
}

func baseReq() *Request {
	return &Request{
		Method:  "GET",
		URL:     "https://api.example.com/v1/feed",
		Headers: http.Header{"User-Agent": {"AdApp/1.0"}, "X-Keep": {"1"}},
	}
}

// ① Response script filters an "ad" field out of a JSON body —
// the core ad-blocking scenario.
func TestResponseJSONFilter(t *testing.T) {
	code := `
var obj = JSON.parse($response.body);
delete obj.ad;
obj.items = obj.items.filter(function (i) { return !i.is_ad; });
$done({ body: JSON.stringify(obj) });
`
	r := NewRunner([]*Def{def("filter", TypeResponse, code)}, Options{})
	resp := &Response{
		Status:  200,
		Headers: http.Header{"Content-Type": {"application/json"}},
		Body:    []byte(`{"ad":{"id":9},"items":[{"id":1},{"id":2,"is_ad":true}]}`),
	}
	out := r.RunResponse(baseReq().URL, baseReq(), resp)
	body := string(out.Body)
	if strings.Contains(body, `"ad"`) || strings.Contains(body, "is_ad") || strings.Contains(body, `"id":2`) {
		t.Fatalf("ad content survived: %s", body)
	}
	if !strings.Contains(body, `"id":1`) {
		t.Fatalf("legit item lost: %s", body)
	}
}

// ② Request script deletes and rewrites headers.
func TestRequestHeaderRewrite(t *testing.T) {
	code := `
var h = $request.headers;
delete h["user-agent"];
h["x-keep"] = "2";
h["x-added"] = "yes";
$done({ headers: h });
`
	r := NewRunner([]*Def{def("hdr", TypeRequest, code)}, Options{})
	out := r.RunRequest(baseReq())
	if out.Respond != nil {
		t.Fatal("unexpected short-circuit")
	}
	if got := out.Headers.Get("User-Agent"); got != "" {
		t.Fatalf("User-Agent not deleted: %q", got)
	}
	if got := out.Headers.Get("X-Keep"); got != "2" {
		t.Fatalf("X-Keep = %q, want 2", got)
	}
	if got := out.Headers.Get("X-Added"); got != "yes" {
		t.Fatalf("X-Added = %q, want yes", got)
	}
}

// ③ $done({response:{...}}) rejects the request outright.
func TestDoneReject(t *testing.T) {
	code := `$done({ response: { status: 403, headers: {"Content-Type": "text/plain"}, body: "blocked" } });`
	r := NewRunner([]*Def{def("block", TypeRequest, code)}, Options{})
	out := r.RunRequest(baseReq())
	if out.Respond == nil {
		t.Fatal("expected short-circuit response")
	}
	if out.Respond.Status != 403 || string(out.Respond.Body) != "blocked" {
		t.Fatalf("respond = %d %q", out.Respond.Status, out.Respond.Body)
	}
}

// ④ $persistentStore round-trips, including across Runner
// instances sharing one backing file (0600).
func TestPersistentStoreRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "store.json")
	code := `
var prev = $persistentStore.read("counter");
var n = prev === null ? 1 : parseInt(prev) + 1;
$persistentStore.write(String(n), "counter");
$done({});
`
	r1 := NewRunner([]*Def{def("count", TypeRequest, code)}, Options{StorePath: p})
	r1.RunRequest(baseReq())
	r1.RunRequest(baseReq())
	r2 := NewRunner([]*Def{def("count", TypeRequest, code)}, Options{StorePath: p})
	got, ok := r2.storeRead("counter")
	if !ok || got != "2" {
		t.Fatalf("store readback = %q, %v; want \"2\"", got, ok)
	}
}

// ⑤ An infinite-loop script is killed by the hard timeout and
// the runner keeps serving afterwards.
func TestInfiniteLoopKilled(t *testing.T) {
	loop := def("loop", TypeRequest, `while (true) {}`)
	loop.Timeout = 300 * time.Millisecond
	good := def("good", TypeResponse, `$done({ body: "fine" });`)
	r := NewRunner([]*Def{loop, good}, Options{})
	start := time.Now()
	out := r.RunRequest(baseReq())
	if time.Since(start) > 3*time.Second {
		t.Fatalf("loop script not interrupted promptly: %v", time.Since(start))
	}
	if out.Respond != nil {
		t.Fatal("timed-out script must pass through")
	}
	infos := r.Infos()
	if infos[0].LastOK || !strings.Contains(infos[0].LastErr, "超时") {
		t.Fatalf("loop stat = %+v", infos[0])
	}
	// Runner still alive:
	resp := r.RunResponse(baseReq().URL, baseReq(), &Response{Status: 200, Headers: http.Header{}, Body: []byte("x")})
	if string(resp.Body) != "fine" {
		t.Fatalf("runner broken after timeout kill: %q", resp.Body)
	}
}

// ⑥ A syntax-error script reports a readable error and harms
// nothing; a runtime error behaves the same.
func TestBrokenScriptsPassThrough(t *testing.T) {
	syn := def("syntax", TypeRequest, `this is not javascript {{{`)
	rt := def("runtime", TypeRequest, `throw new Error("boom-42");`)
	r := NewRunner([]*Def{syn, rt}, Options{})
	out := r.RunRequest(baseReq()) // must not panic
	if out.Respond != nil || out.URL != baseReq().URL {
		t.Fatalf("broken scripts altered the request: %+v", out)
	}
	infos := r.Infos()
	if !strings.Contains(infos[0].LastErr, "编译失败") {
		t.Fatalf("syntax stat = %+v", infos[0])
	}
	if !strings.Contains(infos[1].LastErr, "boom-42") {
		t.Fatalf("runtime stat = %+v", infos[1])
	}
	found := false
	for _, l := range r.Logs() {
		if strings.Contains(l.Text, "boom-42") {
			found = true
		}
	}
	if !found {
		t.Fatal("runtime error missing from engine log")
	}
}

// $httpClient with $done inside the callback (classic pattern).
func TestHTTPClientCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		w.Header().Set("X-Srv", "ok")
		_, _ = w.Write([]byte("remote-body"))
	}))
	defer srv.Close()
	code := `
$httpClient.get("` + srv.URL + `/data", function (error, response, data) {
  if (error) { $done({}); return; }
  $done({ body: data + "|" + response.status });
});
`
	d := def("fetch", TypeResponse, code)
	r := NewRunner([]*Def{d}, Options{})
	out := r.RunResponse(baseReq().URL, baseReq(), &Response{Status: 200, Headers: http.Header{}, Body: []byte("orig")})
	if string(out.Body) != "remote-body|200" {
		t.Fatalf("body = %q", out.Body)
	}
}

// QX $task.fetch promise form maps onto the same transport.
func TestTaskFetchPromise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		_, _ = w.Write([]byte("qx-body"))
	}))
	defer srv.Close()
	code := `
$task.fetch({ url: "` + srv.URL + `" }).then(function (resp) {
  $persistentStore.write(resp.body, "qx");
  $done({});
}, function (e) { $done({}); });
`
	r := NewRunner([]*Def{def("qx", TypeRequest, code)}, Options{})
	r.RunRequest(baseReq())
	if v, ok := r.storeRead("qx"); !ok || v != "qx-body" {
		t.Fatalf("$task.fetch result = %q, %v", v, ok)
	}
}

// console.log and $notification.post land in the engine log /
// notification list.
func TestConsoleAndNotification(t *testing.T) {
	code := `
console.log("hello", 42);
$notification.post("标题", "副", "正文");
$done({});
`
	r := NewRunner([]*Def{def("noisy", TypeRequest, code)}, Options{})
	r.RunRequest(baseReq())
	var sawLog bool
	for _, l := range r.Logs() {
		if strings.Contains(l.Text, "hello 42") {
			sawLog = true
		}
	}
	if !sawLog {
		t.Fatalf("console.log missing: %+v", r.Logs())
	}
	notes := r.Notifications()
	if len(notes) != 1 || notes[0].Title != "标题" || notes[0].Body != "正文" {
		t.Fatalf("notifications = %+v", notes)
	}
}

// Unimplemented APIs raise readable errors (never silent).
func TestUnsupportedAPIReadable(t *testing.T) {
	r := NewRunner([]*Def{def("api", TypeRequest, `$httpAPI("GET", "/v1/x", null, function(){});`)}, Options{})
	r.RunRequest(baseReq())
	infos := r.Infos()
	if infos[0].LastOK || !strings.Contains(infos[0].LastErr, "$httpAPI") {
		t.Fatalf("stat = %+v", infos[0])
	}
}

// FromEngine: unsupported types (cron) are carried as
// non-runnable, patterns compile, SHA passes through.
func TestFromEngine(t *testing.T) {
	ed := &surge.EngineData{Scripts: []surge.ScriptDef{
		{Name: "cronjob", Params: map[string]string{"type": "cron"},
			Resolved: &surge.ResolvedScript{Type: "cron", Code: "$done({})", Enabled: true, Source: "https://x/y.js"}},
		{Name: "resp", Params: map[string]string{"type": "http-response", "pattern": `ads\.example`},
			Resolved: &surge.ResolvedScript{Type: "http-response", Pattern: `ads\.example`, Code: "$done({})", Enabled: true, SHA256: "ab12"}},
	}}
	defs := FromEngine(ed)
	if len(defs) != 2 {
		t.Fatal(len(defs))
	}
	if defs[0].Supported {
		t.Fatal("cron must be unsupported")
	}
	r := NewRunner(defs, Options{})
	if r.Runnable(TypeResponse, "https://other.example/feed") {
		t.Fatal("pattern should not match other host")
	}
	if !r.Runnable(TypeResponse, "https://ads.example.com/feed") {
		t.Fatal("pattern should match ads host")
	}
	if defs[1].SHA256 != "ab12" {
		t.Fatalf("sha = %q", defs[1].SHA256)
	}
}
