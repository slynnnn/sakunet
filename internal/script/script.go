// Package script is SakuNet's JavaScript engine for Surge-style
// scripts (v1.1). It executes http-request / http-response scripts
// inside the MITM layer via goja (a pure-Go JS runtime), with a
// hard per-run timeout, a persistent key/value store, and a full
// execution log. Other Surge script types (cron, event, ...) are
// preserved by the importer and reported as unsupported here —
// they are never silently dropped and never executed.
//
// Supported Surge API subset:
//
//	$request, $response, $done, $persistentStore,
//	$notification.post, $httpClient.get/post, console.log
//
// QX compatibility (thin mapping, see vm.go):
//
//	$task.fetch (promise form), $prefs.valueForKey/setValueForKey,
//	$notify
//
// Anything outside the subset raises a readable JS error that is
// captured in the engine log; a failing or runaway script never
// breaks the proxied connection (Surge semantics: on error the
// request/response passes through unmodified).
package script

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"sakunet/internal/surge"
)

// DefaultTimeout bounds one script run when the definition carries
// no timeout parameter.
const DefaultTimeout = 10 * time.Second

// Type names as they appear in Surge [Script] definitions.
const (
	TypeRequest  = "http-request"
	TypeResponse = "http-response"
)

// Def is one executable (or explicitly non-executable) script.
type Def struct {
	Name         string
	Type         string // as written in the config (lower-cased)
	Pattern      string
	Source       string // human-readable origin: 配置名 / 模块名 / URL
	Timeout      time.Duration
	RequiresBody bool
	Enabled      bool
	Supported    bool   // type is http-request / http-response
	Code         string // JS source; empty when LoadErr != ""
	LoadErr      string // resolution/compile failure, human-readable
	SHA256       string

	re *regexp.Regexp

	once    sync.Once
	prog    *goja.Program
	compErr string
}

// Match reports whether the script applies to a full URL. A script
// without a pattern matches everything.
func (d *Def) Match(url string) bool {
	if d.re == nil {
		return true
	}
	return d.re.MatchString(url)
}

// Info is the panel-facing view of one script definition.
type Info struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Source    string `json:"source,omitempty"`
	Enabled   bool   `json:"enabled"`
	Supported bool   `json:"supported"`
	LoadErr   string `json:"load_error,omitempty"`
	LastRun   string `json:"last_run,omitempty"` // RFC3339 or ""
	LastOK    bool   `json:"last_ok"`
	LastErr   string `json:"last_error,omitempty"`
	LastMS    int64  `json:"last_ms,omitempty"`
}

// FromEngine builds the executable definition list from imported
// engine data. Scripts the importer could not resolve arrive with
// Resolved == nil or a LoadError and are carried through as
// non-runnable entries so the panel can show exactly what is wrong.
func FromEngine(e *surge.EngineData) []*Def {
	defs := make([]*Def, 0, len(e.Scripts))
	for _, sd := range e.Scripts {
		defs = append(defs, defFromSurge(sd))
	}
	return defs
}

func defFromSurge(sd surge.ScriptDef) *Def {
	d := &Def{Name: sd.Name, Enabled: true}
	r := sd.Resolved
	if r == nil {
		// Unresolved (e.g. offline report mode): fall back to the raw
		// params so type/pattern still display correctly.
		d.Type = strings.ToLower(strings.TrimSpace(sd.Params["type"]))
		d.Pattern = sd.Params["pattern"]
		d.Source = "Surge 配置"
		d.LoadErr = "脚本源码尚未解析（请在面板重新导入配置）"
	} else {
		d.Type = strings.ToLower(strings.TrimSpace(r.Type))
		d.Pattern = r.Pattern
		d.Source = r.Source
		d.Code = r.Code
		d.LoadErr = r.LoadError
		d.SHA256 = r.SHA256
		d.RequiresBody = r.RequiresBody
		d.Enabled = r.Enabled
		if r.TimeoutSec > 0 {
			d.Timeout = time.Duration(r.TimeoutSec) * time.Second
		}
	}
	d.Supported = d.Type == TypeRequest || d.Type == TypeResponse
	if d.Supported && d.LoadErr == "" && d.Code == "" {
		d.LoadErr = "脚本源码为空"
	}
	if d.Pattern != "" {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			d.LoadErr = "pattern 正则无法编译：" + err.Error()
		} else {
			d.re = re
		}
	}
	if d.Timeout <= 0 {
		d.Timeout = DefaultTimeout
	}
	return d
}

// Hash returns the hex SHA-256 of a script body (used at import
// time to fingerprint cached remote scripts).
func Hash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Describe summarises a def list for import-report notes.
func Describe(defs []*Def) string {
	var live, unsup, failed int
	for _, d := range defs {
		switch {
		case !d.Supported:
			unsup++
		case d.LoadErr != "":
			failed++
		default:
			live++
		}
	}
	return fmt.Sprintf("脚本引擎：%d 个 http 脚本已上线，%d 个类型暂不支持，%d 个加载失败", live, unsup, failed)
}
