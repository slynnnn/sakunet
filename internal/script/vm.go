package script

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// This file is the goja bridge: one fresh VM per script run, the
// Surge API subset as globals, a hard timeout via vm.Interrupt,
// and $done-result interpretation.
//
// Deliberate semantics (documented in README):
//   - $done() with no argument passes the request/response
//     through, but in-place mutations of $request / $response made
//     before the call are honoured (Loon/QX-style scripts rely on
//     this; strict Surge semantics would ignore them).
//   - $done({...}) applies the given fields on top: url, headers,
//     body, status (response phase) and response:{...} (request
//     phase short-circuit answer = scripted reject/mock).
//   - $done($request) works, since $request carries url/headers.
//   - A script that throws, times out or never calls $done leaves
//     the traffic unmodified; the failure lands in the engine log.
//   - Header objects are exposed with lower-case keys (QX style),
//     so scripts never fight canonicalisation.

var (
	doneSentinel    = &interruptReason{"done"}
	timeoutSentinel = &interruptReason{"timeout"}
)

type interruptReason struct{ kind string }

type runResult struct {
	url     string
	headers http.Header
	body    []byte
	bodySet bool
	status  int
	respond *Response
	// doneRaw is the raw $done({...}) argument object, kept for
	// standalone runs (panel rendering reads title/content/icon
	// from it). Nil when the script called $done() bare or the
	// argument was not an object.
	doneRaw map[string]any
}

func (d *Def) program() (*goja.Program, string) {
	d.once.Do(func() {
		p, err := goja.Compile(d.Name, d.Code, false)
		if err != nil {
			d.compErr = "脚本编译失败：" + err.Error()
			return
		}
		d.prog = p
	})
	return d.prog, d.compErr
}

// runOne executes one script against the current request/response
// state and returns what the script decided. It never panics and
// never blocks meaningfully past the definition's timeout.
func (r *Runner) runOne(d *Def, req *Request, reqBody []byte, resp *Response) *runResult {
	res := &runResult{}
	prog, compErr := d.program()
	if compErr != "" {
		r.recordStat(d, false, compErr, 0)
		r.logf(d.Name, "error", compErr)
		return res
	}
	start := time.Now()
	vm := goja.New()

	// --- $request / $response objects ---
	reqObj := map[string]any{
		"method":  req.Method,
		"url":     req.URL,
		"headers": headersToJS(req.Headers),
	}
	if reqBody != nil {
		reqObj["body"] = string(reqBody)
	}
	_ = vm.Set("$request", reqObj)

	var respObj map[string]any
	if resp != nil {
		respObj = map[string]any{
			"status":  resp.Status,
			"headers": headersToJS(resp.Headers),
			"body":    string(resp.Body),
		}
		_ = vm.Set("$response", respObj)
	}

	// --- $done ---
	var doneVal goja.Value
	_ = vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) > 0 {
			doneVal = call.Arguments[0]
		}
		vm.Interrupt(doneSentinel)
		return goja.Undefined()
	})

	r.installGlobals(vm, d)

	timer := time.AfterFunc(d.Timeout, func() { vm.Interrupt(timeoutSentinel) })
	_, err := vm.RunProgram(prog)
	timer.Stop()
	dur := time.Since(start)

	if err != nil {
		if ie, ok := err.(*goja.InterruptedError); ok {
			switch ie.Value() {
			case doneSentinel:
				// normal completion via $done
			case timeoutSentinel:
				msg := fmt.Sprintf("脚本执行超时（>%s），已强制中断，本次放行原文", d.Timeout)
				r.recordStat(d, false, msg, dur)
				r.logf(d.Name, "error", msg)
				return &runResult{}
			default:
				msg := "脚本被中断：" + ie.String()
				r.recordStat(d, false, msg, dur)
				r.logf(d.Name, "error", msg)
				return &runResult{}
			}
		} else {
			msg := "脚本运行错误：" + err.Error()
			r.recordStat(d, false, msg, dur)
			r.logf(d.Name, "error", msg)
			return &runResult{}
		}
	}
	r.recordStat(d, true, "", dur)

	// Start from the (possibly mutated) live objects.
	if s, ok := reqObj["url"].(string); ok {
		res.url = s
	}
	if respObj != nil {
		if f, ok := toInt(respObj["status"]); ok {
			res.status = f
		}
		if b, ok := respObj["body"].(string); ok && resp != nil && b != string(resp.Body) {
			res.body, res.bodySet = []byte(b), true
		}
	}
	if resp == nil {
		// Request phase: a bare $done() honours header mutations.
		if h := jsToHeaders(reqObj["headers"]); h != nil && !headersEqual(h, req.Headers) {
			res.headers = h
		}
		if reqBody != nil {
			if b, ok := reqObj["body"].(string); ok && b != string(reqBody) {
				res.body, res.bodySet = []byte(b), true
			}
		}
	} else {
		if h := jsToHeaders(respObj["headers"]); h != nil && !headersEqual(h, resp.Headers) {
			res.headers = h
		}
	}

	// Then apply the explicit $done argument on top.
	if doneVal != nil && !goja.IsUndefined(doneVal) && !goja.IsNull(doneVal) {
		obj, ok := doneVal.Export().(map[string]any)
		if ok {
			res.doneRaw = obj
			applyDoneObject(res, obj, resp != nil)
		}
	}
	return res
}

// applyDoneObject folds a $done({...}) argument into the result.
func applyDoneObject(res *runResult, obj map[string]any, isResponsePhase bool) {
	if v, ok := obj["url"].(string); ok && v != "" {
		res.url = v
	}
	if hv, ok := obj["headers"]; ok {
		if h := jsToHeaders(hv); h != nil {
			res.headers = h
		}
	}
	if v, ok := obj["body"].(string); ok {
		res.body, res.bodySet = []byte(v), true
	}
	if isResponsePhase {
		if n, ok := toInt(obj["status"]); ok && n > 0 {
			res.status = n
		}
		return
	}
	// Request phase: {response:{...}} short-circuits the request.
	if rv, ok := obj["response"].(map[string]any); ok {
		rp := &Response{Status: 200, Headers: http.Header{}}
		if n, ok := toInt(rv["status"]); ok && n > 0 {
			rp.Status = n
		}
		if h := jsToHeaders(rv["headers"]); h != nil {
			rp.Headers = h
		}
		if v, ok := rv["body"].(string); ok {
			rp.Body = []byte(v)
		}
		res.respond = rp
	}
}

// --- globals: console / store / notification / http --------------

func (r *Runner) installGlobals(vm *goja.Runtime, d *Def) {
	// console.log & friends -> engine log.
	console := map[string]any{}
	for _, lvl := range []string{"log", "info", "warn", "error", "debug"} {
		level := lvl
		console[level] = func(call goja.FunctionCall) goja.Value {
			parts := make([]string, 0, len(call.Arguments))
			for _, a := range call.Arguments {
				parts = append(parts, jsString(a))
			}
			r.logf(d.Name, "log", strings.Join(parts, " "))
			return goja.Undefined()
		}
	}
	_ = vm.Set("console", console)

	// $persistentStore (Surge) — backed by the runner store.
	store := map[string]any{
		"read": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) < 1 {
				return goja.Null()
			}
			if v, ok := r.storeRead(call.Arguments[0].String()); ok {
				return vm.ToValue(v)
			}
			return goja.Null()
		},
		"write": func(call goja.FunctionCall) goja.Value {
			// Surge signature: write(value, key)
			if len(call.Arguments) < 2 {
				return vm.ToValue(false)
			}
			ok := r.storeWrite(call.Arguments[1].String(), call.Arguments[0].String())
			return vm.ToValue(ok)
		},
	}
	_ = vm.Set("$persistentStore", store)

	// $prefs (QX) mapped onto the same store.
	prefs := map[string]any{
		"valueForKey": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) < 1 {
				return goja.Null()
			}
			if v, ok := r.storeRead(call.Arguments[0].String()); ok {
				return vm.ToValue(v)
			}
			return goja.Null()
		},
		"setValueForKey": func(call goja.FunctionCall) goja.Value {
			// QX signature: setValueForKey(value, key)
			if len(call.Arguments) < 2 {
				return vm.ToValue(false)
			}
			return vm.ToValue(r.storeWrite(call.Arguments[1].String(), call.Arguments[0].String()))
		},
		"removeValueForKey": func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) < 1 {
				return goja.Undefined()
			}
			r.storeWrite(call.Arguments[0].String(), "")
			return goja.Undefined()
		},
	}
	_ = vm.Set("$prefs", prefs)

	// $notification.post (Surge) and $notify (QX).
	notifyFn := func(call goja.FunctionCall) goja.Value {
		arg := func(i int) string {
			if len(call.Arguments) > i {
				return call.Arguments[i].String()
			}
			return ""
		}
		r.notify(d.Name, arg(0), arg(1), arg(2))
		return goja.Undefined()
	}
	_ = vm.Set("$notification", map[string]any{"post": notifyFn})
	_ = vm.Set("$notify", notifyFn)

	// $httpClient.get/post (Surge): callback style, executed
	// synchronously — the callback fires before the call returns,
	// which preserves the visible semantics of the common pattern
	// ($done inside the callback) without an event loop.
	httpClient := map[string]any{
		"get":  r.httpClientMethod(vm, d, http.MethodGet),
		"post": r.httpClientMethod(vm, d, http.MethodPost),
	}
	_ = vm.Set("$httpClient", httpClient)

	// $task.fetch (QX): promise style over the same transport.
	_ = vm.Set("$task", map[string]any{"fetch": r.taskFetch(vm, d)})

	// Known-but-unsupported APIs fail loudly, never silently.
	_ = vm.Set("$httpAPI", func(call goja.FunctionCall) goja.Value {
		panic(vm.NewTypeError("$httpAPI 暂不支持（SakuNet 脚本引擎子集未包含内部 API 调用）"))
	})
}

func (r *Runner) httpClientMethod(vm *goja.Runtime, d *Def, method string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			panic(vm.NewTypeError("$httpClient." + strings.ToLower(method) + " 缺少参数"))
		}
		opts := parseHTTPOpts(call.Arguments[0])
		if method == http.MethodPost && opts.method == "" {
			opts.method = http.MethodPost
		}
		var cb goja.Callable
		if len(call.Arguments) >= 2 {
			cb, _ = goja.AssertFunction(call.Arguments[1])
		}
		status, headers, data, err := r.doHTTP(d, opts)
		if cb == nil {
			return goja.Undefined()
		}
		var errVal goja.Value = goja.Null()
		respVal := goja.Null()
		dataVal := goja.Value(goja.Null())
		if err != nil {
			errVal = vm.ToValue(err.Error())
		} else {
			respVal = vm.ToValue(map[string]any{
				"status":  status,
				"headers": headersToJS(headers),
			})
			dataVal = vm.ToValue(data)
		}
		if _, err := cb(goja.Undefined(), errVal, respVal, dataVal); err != nil {
			panic(err)
		}
		return goja.Undefined()
	}
}

func (r *Runner) taskFetch(vm *goja.Runtime, d *Def) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		promise, resolve, reject := vm.NewPromise()
		if len(call.Arguments) < 1 {
			_ = reject(vm.ToValue(map[string]any{"error": "$task.fetch 缺少参数"}))
			return vm.ToValue(promise)
		}
		opts := parseHTTPOpts(call.Arguments[0])
		status, headers, data, err := r.doHTTP(d, opts)
		if err != nil {
			_ = reject(vm.ToValue(map[string]any{"error": err.Error()}))
		} else {
			_ = resolve(vm.ToValue(map[string]any{
				"statusCode": status,
				"headers":    headersToJS(headers),
				"body":       data,
			}))
		}
		return vm.ToValue(promise)
	}
}

type httpOpts struct {
	url     string
	method  string
	headers map[string]string
	body    string
	timeout time.Duration
}

func parseHTTPOpts(v goja.Value) httpOpts {
	o := httpOpts{headers: map[string]string{}}
	if s, ok := v.Export().(string); ok {
		o.url = s
		return o
	}
	obj, _ := v.Export().(map[string]any)
	if obj == nil {
		return o
	}
	o.url, _ = obj["url"].(string)
	o.method, _ = obj["method"].(string)
	o.body, _ = obj["body"].(string)
	if hv, ok := obj["headers"].(map[string]any); ok {
		for k, val := range hv {
			if s, ok := val.(string); ok {
				o.headers[k] = s
			}
		}
	}
	if n, ok := toInt(obj["timeout"]); ok && n > 0 {
		o.timeout = time.Duration(n) * time.Second
	}
	return o
}

// doHTTP performs one script-initiated HTTP call. Only http/https
// are allowed; the client timeout is capped by the script's own
// budget so a hanging endpoint cannot stall the proxy past it.
func (r *Runner) doHTTP(d *Def, o httpOpts) (int, http.Header, string, error) {
	if o.url == "" {
		return 0, nil, "", fmt.Errorf("缺少 url")
	}
	if !strings.HasPrefix(o.url, "http://") && !strings.HasPrefix(o.url, "https://") {
		return 0, nil, "", fmt.Errorf("$httpClient 只允许 http/https URL：%s", o.url)
	}
	method := strings.ToUpper(o.method)
	if method == "" {
		method = http.MethodGet
	}
	timeout := d.Timeout
	if o.timeout > 0 && o.timeout < timeout {
		timeout = o.timeout
	}
	var body io.Reader
	if o.body != "" {
		body = strings.NewReader(o.body)
	}
	req, err := http.NewRequest(method, o.url, body)
	if err != nil {
		return 0, nil, "", err
	}
	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, "", err
	}
	return resp.StatusCode, resp.Header, string(data), nil
}

// --- value helpers -------------------------------------------------

func jsString(v goja.Value) string {
	if v == nil {
		return ""
	}
	if s, ok := v.Export().(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v.Export())
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// headersToJS exposes headers with lower-case keys (first value
// wins), QX-style.
func headersToJS(h http.Header) map[string]any {
	out := map[string]any{}
	for k, vs := range h {
		lk := strings.ToLower(k)
		if _, dup := out[lk]; dup {
			continue
		}
		if len(vs) > 0 {
			out[lk] = vs[0]
		}
	}
	return out
}

// jsToHeaders converts a JS headers object back to http.Header.
// Returns nil when v is not an object.
func jsToHeaders(v any) http.Header {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	h := http.Header{}
	for k, val := range obj {
		switch s := val.(type) {
		case string:
			h.Set(k, s)
		case nil:
			h.Set(k, "")
		default:
			h.Set(k, fmt.Sprintf("%v", s))
		}
	}
	return h
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, vs := range a {
		bv, ok := b[http.CanonicalHeaderKey(k)]
		if !ok || len(bv) != len(vs) {
			return false
		}
		for i := range vs {
			if bv[i] != vs[i] {
				return false
			}
		}
	}
	return true
}
