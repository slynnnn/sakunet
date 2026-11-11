package surge

import (
	"regexp"
	"strconv"
	"strings"
)

// This file compiles the preserved EngineData ([URL Rewrite] rules)
// into an executable form for SakuNet's MITM/rewrite engine. Rules
// whose Surge encoding has no engine equivalent here are not
// dropped silently: Compile reports them in Unsupported with a
// reason, and the dashboard shows that list.
//
// Supported grammar (per rule line, whitespace separated):
//
//	pattern replacement            -> 302 redirect (Surge default)
//	pattern replacement 302|307    -> redirect, replacement is a
//	                                  regexp substitution ($1 refs)
//	pattern - reject               -> drop the request (403)
//	pattern - reject-200           -> 200 with empty body
//	pattern - reject-img           -> 200 with a 1x1 transparent GIF
//	pattern - reject-dict          -> 200 with "{}" JSON
//	pattern - reject-array         -> 200 with "[]" JSON
//	pattern header-set Name Value  -> set a request header
//	pattern header-add Name Value  -> add a request header
//	pattern header-del Name        -> delete a request header
//	pattern response-header-set Name Value   (also -add / -del)
//
// Header values may contain spaces (everything after the header
// name belongs to the value). Anything else is reported unsupported.

const (
	OpRedirect = "redirect"
	OpReject   = "reject"
	OpHeader   = "header"
)

// CompiledRule is one executable rewrite rule.
type CompiledRule struct {
	Raw       string
	Pattern   string
	Op        string // OpRedirect | OpReject | OpHeader
	Status    int    // redirect: 302/307; reject: HTTP status to answer
	Target    string // redirect: replacement template
	RejectTpl string // reject: "", "empty", "img", "dict", "array"
	Direction string // header: "request" | "response"
	HeaderOp  string // header: "set" | "add" | "del"
	Name      string // header name
	Value     string // header value (set/add)

	re *regexp.Regexp
}

// Match reports whether the rule's pattern matches the full URL.
func (r *CompiledRule) Match(url string) bool { return r.re.MatchString(url) }

// ApplyRedirect performs the regexp substitution for a redirect.
func (r *CompiledRule) ApplyRedirect(url string) string {
	return r.re.ReplaceAllString(url, r.Target)
}

// UnsupportedRule is one preserved rewrite rule the engine cannot
// execute, with the reason.
type UnsupportedRule struct {
	Raw    string `json:"raw"`
	Reason string `json:"reason"`
}

// CompiledEngine is the executable form of EngineData.
type CompiledEngine struct {
	Rules       []*CompiledRule
	Unsupported []UnsupportedRule
}

// Compile compiles preserved rewrite rules. Bad regexes and
// unknown kinds land in Unsupported; Compile never panics.
func (e *EngineData) Compile() *CompiledEngine {
	ce := &CompiledEngine{}
	for _, rr := range e.URLRewrites {
		cr, reason := compileRule(rr.Raw)
		if cr == nil {
			ce.Unsupported = append(ce.Unsupported, UnsupportedRule{Raw: rr.Raw, Reason: reason})
			continue
		}
		ce.Rules = append(ce.Rules, cr)
	}
	return ce
}

func compileRule(raw string) (*CompiledRule, string) {
	toks := strings.Fields(raw)
	if len(toks) < 2 {
		return nil, "字段不足（需要 pattern 与目标）"
	}
	pattern := toks[0]
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, "正则无法编译：" + err.Error()
	}
	cr := &CompiledRule{Raw: raw, Pattern: pattern, re: re}

	// Header form: pattern <op> Name [Value...]
	if isHeaderOp(toks[1]) {
		op := strings.ToLower(toks[1])
		cr.Op = OpHeader
		cr.Direction = "request"
		if strings.HasPrefix(op, "response-") {
			cr.Direction = "response"
			op = strings.TrimPrefix(op, "response-")
		}
		op = strings.TrimPrefix(op, "request-")
		op = strings.TrimPrefix(op, "header-")
		if op == "replace" {
			op = "set"
		}
		cr.HeaderOp = op
		if len(toks) < 3 {
			return nil, "header 规则缺少头名"
		}
		cr.Name = toks[2]
		if op != "del" {
			if len(toks) < 4 {
				return nil, "header 规则缺少头值"
			}
			// Value = everything after "pattern op name" in the raw
			// line, so values may contain spaces.
			cr.Value = strings.TrimSpace(rawAfterFields(raw, 3))
		}
		return cr, ""
	}

	// Redirect / reject form: pattern replacement [kind]
	target := toks[1]
	kind := "302"
	if len(toks) >= 3 {
		kind = strings.ToLower(toks[2])
	}
	switch kind {
	case "302", "307":
		cr.Op = OpRedirect
		cr.Status, _ = strconv.Atoi(kind)
		cr.Target = target
		return cr, ""
	case "reject":
		cr.Op = OpReject
		cr.Status = 403
		cr.RejectTpl = "empty"
		return cr, ""
	case "reject-200":
		cr.Op = OpReject
		cr.Status = 200
		cr.RejectTpl = "empty"
		return cr, ""
	case "reject-img":
		cr.Op = OpReject
		cr.Status = 200
		cr.RejectTpl = "img"
		return cr, ""
	case "reject-dict":
		cr.Op = OpReject
		cr.Status = 200
		cr.RejectTpl = "dict"
		return cr, ""
	case "reject-array":
		cr.Op = OpReject
		cr.Status = 200
		cr.RejectTpl = "array"
		return cr, ""
	}
	return nil, "重写类型 " + kind + " 暂不支持（支持 302/307、reject 类与 header 类）"
}

func isHeaderOp(tok string) bool {
	t := strings.ToLower(tok)
	t = strings.TrimPrefix(t, "response-")
	t = strings.TrimPrefix(t, "request-")
	switch t {
	case "header-set", "header-add", "header-del",
		"header-replace": // replace == set semantics here
		return true
	}
	return false
}

// rawAfterFields returns the remainder of s after skipping n
// whitespace-separated fields, trimmed.
func rawAfterFields(s string, n int) string {
	i := 0
	for f := 0; f < n && i < len(s); f++ {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
	}
	return strings.TrimSpace(s[i:])
}
