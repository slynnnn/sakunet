package script

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Options configure a Runner.
type Options struct {
	// StorePath is the $persistentStore backing file (created
	// 0600). Empty = in-memory only (tests).
	StorePath string
	Log       *log.Logger
}

// LogEntry is one engine-log line (console.log, errors,
// notifications).
type LogEntry struct {
	At     string `json:"at"`
	Script string `json:"script,omitempty"`
	Level  string `json:"level"` // log | warn | error | notify
	Text   string `json:"text"`
}

// Notification is one $notification.post / $notify call.
type Notification struct {
	At       string `json:"at"`
	Script   string `json:"script,omitempty"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body,omitempty"`
}

type runStat struct {
	at  time.Time
	ok  bool
	err string
	ms  int64
}

// Runner executes script definitions against proxied traffic.
// It is safe for concurrent use: every run gets a fresh JS VM.
type Runner struct {
	defs []*Def

	mu       sync.Mutex
	store    map[string]string
	storePth string
	logs     []LogEntry
	notes    []Notification
	stats    map[string]*runStat
	logw     *log.Logger
}

const maxLogEntries = 300

// NewRunner builds a Runner from definitions (see FromEngine).
func NewRunner(defs []*Def, opts Options) *Runner {
	r := &Runner{
		defs:     defs,
		store:    map[string]string{},
		storePth: opts.StorePath,
		stats:    map[string]*runStat{},
		logw:     opts.Log,
	}
	if opts.StorePath != "" {
		if raw, err := os.ReadFile(opts.StorePath); err == nil {
			_ = json.Unmarshal(raw, &r.store)
		}
		if r.store == nil {
			r.store = map[string]string{}
		}
	}
	return r
}

// Defs returns the definitions the runner was built with.
func (r *Runner) Defs() []*Def { return r.defs }

// Runnable reports whether any script can execute for the given
// phase ("http-request" / "http-response") and URL.
func (r *Runner) Runnable(phase, url string) bool {
	for _, d := range r.defs {
		if d.Type == phase && d.Enabled && d.Supported && d.LoadErr == "" && d.Match(url) {
			return true
		}
	}
	return false
}

// NeedsBody reports whether any matching request script declared
// requires-body (only then does the MITM layer buffer the body).
func (r *Runner) NeedsBody(url string) bool {
	for _, d := range r.defs {
		if d.Type == TypeRequest && d.Enabled && d.Supported && d.LoadErr == "" && d.RequiresBody && d.Match(url) {
			return true
		}
	}
	return false
}

// Infos returns the panel view of all definitions, freshest run
// results included.
func (r *Runner) Infos() []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Info, 0, len(r.defs))
	for _, d := range r.defs {
		in := Info{
			Name: d.Name, Type: d.Type, Source: d.Source,
			Enabled: d.Enabled, Supported: d.Supported, LoadErr: d.LoadErr,
		}
		if st, ok := r.stats[d.Name]; ok {
			in.LastRun = st.at.Format(time.RFC3339)
			in.LastOK = st.ok
			in.LastErr = st.err
			in.LastMS = st.ms
		}
		out = append(out, in)
	}
	return out
}

// Logs returns the most recent engine-log entries (oldest first).
func (r *Runner) Logs() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]LogEntry{}, r.logs...)
}

// Notifications returns recorded $notification.post calls.
func (r *Runner) Notifications() []Notification {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Notification{}, r.notes...)
}

func (r *Runner) logf(script, level, text string) {
	if r.logw != nil {
		r.logw.Printf("[script] %s %s: %s", script, level, text)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, LogEntry{
		At: time.Now().Format(time.RFC3339), Script: script, Level: level, Text: text,
	})
	if len(r.logs) > maxLogEntries {
		r.logs = r.logs[len(r.logs)-maxLogEntries:]
	}
}

func (r *Runner) notify(script, title, subtitle, body string) {
	r.mu.Lock()
	r.notes = append(r.notes, Notification{
		At: time.Now().Format(time.RFC3339), Script: script,
		Title: title, Subtitle: subtitle, Body: body,
	})
	if len(r.notes) > maxLogEntries {
		r.notes = r.notes[len(r.notes)-maxLogEntries:]
	}
	r.mu.Unlock()
	r.logf(script, "notify", title+" "+body)
}

func (r *Runner) recordStat(d *Def, ok bool, errText string, dur time.Duration) {
	r.mu.Lock()
	r.stats[d.Name] = &runStat{at: time.Now(), ok: ok, err: errText, ms: dur.Milliseconds()}
	r.mu.Unlock()
}

// --- $persistentStore backing ------------------------------------

func (r *Runner) storeRead(key string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.store[key]
	return v, ok
}

func (r *Runner) storeWrite(key, value string) bool {
	r.mu.Lock()
	r.store[key] = value
	raw, _ := json.Marshal(r.store)
	pth := r.storePth
	r.mu.Unlock()
	if pth != "" {
		if err := os.WriteFile(pth, raw, 0o600); err != nil {
			r.logf("", "error", "$persistentStore 落盘失败："+err.Error())
			return false
		}
	}
	return true
}

// --- Request / response values exchanged with the MITM layer -----

// Request is the script-visible request.
type Request struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte // only when a matching script requires the body
}

// Response is the script-visible response.
type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// ReqOutcome is the result of the http-request script chain.
type ReqOutcome struct {
	// Respond, when non-nil, short-circuits the request: the MITM
	// layer answers with this response instead of forwarding
	// (script-driven reject / mock).
	Respond  *Response
	URL      string      // possibly rewritten URL
	Headers  http.Header // possibly replaced headers
	Body     []byte      // possibly replaced body (BodySet marks it)
	BodySet  bool
	RanCount int
}

// RunRequest runs all matching http-request scripts in definition
// order. A script error aborts that script only; the chain
// continues with the last good state (Surge-compatible leniency).
func (r *Runner) RunRequest(req *Request) *ReqOutcome {
	out := &ReqOutcome{URL: req.URL, Headers: req.Headers, Body: req.Body}
	cur := &Request{Method: req.Method, URL: req.URL, Headers: cloneHeader(req.Headers), Body: req.Body}
	for _, d := range r.defs {
		if d.Type != TypeRequest || !d.Enabled || !d.Supported || d.LoadErr != "" || !d.Match(cur.URL) {
			continue
		}
		body := []byte(nil)
		if d.RequiresBody {
			body = cur.Body
		}
		res := r.runOne(d, cur, body, nil)
		out.RanCount++
		if res.respond != nil {
			out.Respond = res.respond
			return out
		}
		if res.url != "" {
			cur.URL = res.url
		}
		if res.headers != nil {
			cur.Headers = res.headers
		}
		if res.bodySet && d.RequiresBody {
			cur.Body = res.body
			out.BodySet = true
		}
		out.URL, out.Headers, out.Body = cur.URL, cur.Headers, cur.Body
	}
	return out
}

// RunResponse runs all matching http-response scripts in
// definition order and returns the (possibly modified) response.
func (r *Runner) RunResponse(url string, req *Request, resp *Response) *Response {
	cur := &Response{Status: resp.Status, Headers: cloneHeader(resp.Headers), Body: resp.Body}
	for _, d := range r.defs {
		if d.Type != TypeResponse || !d.Enabled || !d.Supported || d.LoadErr != "" || !d.Match(url) {
			continue
		}
		res := r.runOne(d, req, nil, cur)
		if res.status != 0 {
			cur.Status = res.status
		}
		if res.headers != nil {
			cur.Headers = res.headers
		}
		if res.bodySet {
			cur.Body = res.body
		}
	}
	return cur
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return http.Header{}
	}
	return h.Clone()
}
