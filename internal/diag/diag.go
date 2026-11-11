// Package diag implements SakuNet's one-click self-check and the
// redacted diagnostics bundle. The design goal: the user never has
// to describe a technical symptom — they run the check, and if that
// is not enough they send back a bundle that is safe to share
// because every credential value has been scrubbed out of it.
package diag

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"sakunet/internal/api"
	"sakunet/internal/core"
	"sakunet/internal/sysproxy"
)

// Check is one self-check line for the panel.
type Check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"` // pass | fail | na
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"` // one plain-language action when fail
}

// RunChecks executes every check for real (no canned answers) and
// returns the results in display order.
func RunChecks(mgr *core.Manager, clash *api.Client) []Check {
	st := mgr.Status()
	sum := mgr.ConfigSummary()
	var out []Check
	add := func(c Check) { out = append(out, c) }

	// 1. Core running.
	if st.Running {
		add(Check{ID: "core", Name: "内核正在运行", State: "pass", Detail: st.Version})
	} else {
		add(Check{ID: "core", Name: "内核正在运行", State: "fail",
			Detail: errOr(st.Error, "内核未启动"),
			Hint:   "点首页右上角的大开关启动；还不行就导出诊断包发回来。"})
	}

	// 2. Panel <-> core communication (clash API).
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	_, verr := clash.Version(ctx)
	cancel()
	if !st.Running {
		add(Check{ID: "clash", Name: "面板与内核通信", State: "na", Detail: "内核未运行"})
	} else if verr == nil {
		add(Check{ID: "clash", Name: "面板与内核通信", State: "pass"})
	} else {
		add(Check{ID: "clash", Name: "面板与内核通信", State: "fail", Detail: verr.Error(),
			Hint: "在设置页点「重启内核」；仍不通就导出诊断包发回来。"})
	}

	// 3. DNS resolution.
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	ips, derr := net.DefaultResolver.LookupHost(dctx, "cp.cloudflare.com")
	dcancel()
	if derr == nil && len(ips) > 0 {
		add(Check{ID: "dns", Name: "DNS 解析", State: "pass", Detail: "cp.cloudflare.com → " + ips[0]})
	} else {
		add(Check{ID: "dns", Name: "DNS 解析", State: "fail", Detail: errStr(derr),
			Hint: "检查这台电脑的网络连接与 DNS 设置；换个网络（如手机热点）再试一次。"})
	}

	// 4. Real request through the current exit.
	if !st.Running {
		add(Check{ID: "egress", Name: "经当前出口上网", State: "na", Detail: "内核未运行"})
	} else {
		code, eerr := egressProbe(mgr.SysproxyAddr())
		if eerr == nil && code == 204 {
			add(Check{ID: "egress", Name: "经当前出口上网", State: "pass", Detail: "测试请求返回 204（连通）"})
		} else {
			add(Check{ID: "egress", Name: "经当前出口上网", State: "fail",
				Detail: fmt.Sprintf("状态码 %d / %s", code, errStr(eerr)),
				Hint:   "在首页换一个节点再点自检；全部节点都不通，多半是这批节点或本地网络的问题。"})
		}
	}

	// 5. Rule-set loading state.
	switch {
	case !sum.Exists:
		add(Check{ID: "rulesets", Name: "规则集加载", State: "na", Detail: "尚未生成配置"})
	case sum.RuleSets == 0:
		add(Check{ID: "rulesets", Name: "规则集加载", State: "pass", Detail: "当前配置未引用远程规则集"})
	case !st.Running:
		add(Check{ID: "rulesets", Name: "规则集加载", State: "na", Detail: fmt.Sprintf("配置引用 %d 个规则集，内核未运行", sum.RuleSets)})
	default:
		add(Check{ID: "rulesets", Name: "规则集加载", State: "pass",
			Detail: fmt.Sprintf("配置引用 %d 个远程规则集，内核已按此配置启动", sum.RuleSets)})
	}

	// 6. MITM engine & CA.
	mi := st.MITM
	switch {
	case mi == nil || (mi.Hostnames == 0 && mi.RulesOK == 0 && mi.CASubject == ""):
		add(Check{ID: "mitm", Name: "MITM 引擎与 CA", State: "na", Detail: "导入的配置没有 MITM/重写内容"})
	case mi.State == "running":
		add(Check{ID: "mitm", Name: "MITM 引擎与 CA", State: "pass",
			Detail: fmt.Sprintf("%s · 主机名 %d · 规则 %d", mi.Addr, mi.Hostnames, mi.RulesOK)})
	default:
		add(Check{ID: "mitm", Name: "MITM 引擎与 CA", State: "fail", Detail: errOr(mi.Reason, "引擎待机"),
			Hint: "多半是配置里没有可用的 CA：在 Surge 里打开这份配置的 MITM 设置生成 CA 后，重新导入一次。"})
	}

	// 7. System proxy pointing (Windows only).
	if runtime.GOOS != "windows" {
		add(Check{ID: "sysproxy", Name: "系统代理指向", State: "na", Detail: "仅 Windows 适用"})
	} else if st.Tun {
		add(Check{ID: "sysproxy", Name: "系统代理指向", State: "na", Detail: "TUN 模式已开启，不依赖系统代理"})
	} else {
		en, srv, serr := sysproxy.Current()
		want := mgr.SysproxyAddr()
		switch {
		case serr != nil:
			add(Check{ID: "sysproxy", Name: "系统代理指向", State: "fail", Detail: serr.Error(),
				Hint: "导出诊断包发回来定位。"})
		case en && (srv == want || srv == "127.0.0.1:2080" || srv == "127.0.0.1:2081"):
			add(Check{ID: "sysproxy", Name: "系统代理指向", State: "pass", Detail: "系统代理 → " + srv})
		case en:
			add(Check{ID: "sysproxy", Name: "系统代理指向", State: "fail", Detail: "系统代理当前指向 " + srv,
				Hint: "在设置页「系统代理」点一次开启，让它指回 SakuNet。"})
		default:
			add(Check{ID: "sysproxy", Name: "系统代理指向", State: "fail", Detail: "系统代理未开启",
				Hint: "在设置页「系统代理」点开启；或开启 TUN 模式接管全机流量。"})
		}
	}
	return out
}

func egressProbe(proxyAddr string) (int, error) {
	tr := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr})}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := client.Get("http://cp.cloudflare.com/generate_204")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func errOr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ = strings.TrimSpace
