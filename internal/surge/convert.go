package surge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sakunet/internal/config"
)

// convertProxy converts one [Proxy] line into a config.Node.
// Returns (nil, reason) when the line cannot be migrated.
// noteIgnored records parameters that have no sing-box equivalent.
func convertProxy(pl rawLine, noteIgnored func(typ, key string)) (*config.Node, string) {
	if len(pl.fields) < 3 {
		return nil, "字段不足（需要 类型, 服务器, 端口）"
	}
	typ := strings.ToLower(pl.fields[0])
	n := &config.Node{Name: pl.name, Server: pl.fields[1], Port: atoi(pl.fields[2], 0)}
	if n.Port == 0 {
		return nil, "端口无法解析"
	}
	_, kv := params(pl.fields[3:])
	used := map[string]bool{}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := kv[k]; ok {
				used[k] = true
				return v
			}
		}
		return ""
	}
	sni := get("sni", "server-name", "peer")
	if sni != "" {
		n.SNI = sni
	}
	if truthy(get("skip-cert-verify", "skip-cert-verification")) {
		n.Insecure = true
	}
	if truthy(get("tfo", "fast-open")) {
		n.TFO = true
	}

	switch typ {
	case "snell":
		n.Type = "snell"
		n.PSK = get("psk")
		if n.PSK == "" {
			return nil, "缺少 psk"
		}
		n.Version = atoi(get("version"), 4)
		switch n.Version {
		case 4, 5, 6:
		default:
			return nil, fmt.Sprintf("snell v%d 在 sing-box 无对应实现（仅 v4/v5/v6）", n.Version)
		}
		if n.Version == 6 {
			if m := get("mode"); m != "" {
				n.Mode = m
			}
		}
	case "anytls":
		n.Type = "anytls"
		n.Password = get("password")
		if n.Password == "" {
			return nil, "缺少 password"
		}
	case "hysteria2", "hy2":
		n.Type = "hysteria2"
		n.Password = get("password")
		if n.Password == "" {
			return nil, "缺少 password"
		}
		if get("obfs") == "salamander" || get("obfs-password") != "" {
			n.ObfsPassword = get("obfs-password", "obfs-param")
		}
	case "naive":
		n.Type = "naive"
		n.Username = get("username")
		n.Password = get("password")
		if n.Password == "" {
			return nil, "缺少 password"
		}
		n.TLS = true
	case "ss", "shadowsocks":
		n.Type = "shadowsocks"
		n.Method = get("encrypt-method", "method")
		n.Password = get("password")
		if n.Method == "" || n.Password == "" {
			return nil, "缺少 encrypt-method 或 password"
		}
		switch get("obfs") {
		case "http", "tls":
			n.Plugin = "obfs-local"
			opts := "obfs=" + get("obfs")
			if h := get("obfs-host"); h != "" {
				opts += ";obfs-host=" + h
			}
			if u := get("obfs-uri"); u != "" {
				opts += ";obfs-uri=" + u
			}
			n.PluginOpts = opts
		}
	case "trojan":
		n.Type = "trojan"
		n.Password = get("password")
		if n.Password == "" {
			return nil, "缺少 password"
		}
		applyTransport(n, get, kv, used)
	case "vmess":
		n.Type = "vmess"
		n.UUID = get("username", "uuid")
		if n.UUID == "" {
			return nil, "缺少 username（uuid）"
		}
		n.AlterID = atoi(get("alterid", "alter-id"), 0)
		if s := get("encrypt-method", "security"); s != "" {
			n.Security = s
		}
		if truthy(get("tls")) {
			n.TLS = true
		}
		applyTransport(n, get, kv, used)
	case "vless":
		n.Type = "vless"
		n.UUID = get("username", "uuid")
		if n.UUID == "" {
			return nil, "缺少 username（uuid）"
		}
		n.Flow = get("flow")
		if truthy(get("tls")) || n.Flow != "" {
			n.TLS = true
		}
		if pk := get("reality-base64-pubkey", "reality-pubkey", "reality-public-key", "pk"); pk != "" {
			n.RealityPublicKey = pk
			n.RealityShortID = get("reality-short-id", "reality-shortid", "sid")
			n.TLS = true
		}
		applyTransport(n, get, kv, used)
	case "http":
		n.Type = "http"
		n.Username = get("username")
		n.Password = get("password")
		if truthy(get("tls")) {
			n.TLS = true
		}
	case "https":
		n.Type = "http"
		n.Username = get("username")
		n.Password = get("password")
		n.TLS = true
	case "socks5":
		n.Type = "socks"
		n.Username = get("username")
		n.Password = get("password")
		if truthy(get("tls")) {
			n.TLS = true
		}
	case "socks5-tls":
		n.Type = "socks"
		n.Username = get("username")
		n.Password = get("password")
		n.TLS = true
	case "direct":
		return nil, "DIRECT 别名无需迁移（内置 direct 出站）"
	default:
		return nil, fmt.Sprintf("协议 %s 暂不支持导入", typ)
	}
	for k := range kv {
		if !used[k] {
			noteIgnored(typ, k)
		}
	}
	return n, ""
}

// applyTransport reads ws/grpc transport parameters shared by
// trojan/vmess/vless lines.
func applyTransport(n *config.Node, get func(...string) string, kv map[string]string, used map[string]bool) {
	if truthy(get("ws")) {
		n.Network = "ws"
		n.WSPath = get("ws-path")
		if h := get("ws-headers"); h != "" {
			if m := regexp.MustCompile(`(?i)"?host"?\s*[:=]\s*"?([^",}]+)"?`).FindStringSubmatch(h); m != nil {
				n.WSHost = strings.TrimSpace(m[1])
			}
		}
		if n.WSHost == "" {
			n.WSHost = get("ws-host")
		}
	}
	if truthy(get("grpc")) {
		n.Network = "grpc"
		n.ServiceName = get("grpc-servicename", "grpc-service-name", "service-name")
	}
}

// convertGroup converts one [Proxy Group] line. Members come from
// explicit tokens, include-all-proxies, include-other-group and
// policy-regex-filter, in Surge's spirit (intersection of the
// include set with the regex filter).
func convertGroup(gl rawLine, nodeByName map[string]*config.Node, nodeTags []string, groupNames map[string]bool) (*GroupDef, string, []string) {
	if len(gl.fields) == 0 {
		return nil, "空行", nil
	}
	typ := strings.ToLower(gl.fields[0])
	pos, kv := params(gl.fields[1:])
	var notes []string

	memberSet := []string{}
	seen := map[string]bool{}
	add := func(tag string) {
		if tag != "" && !seen[tag] {
			seen[tag] = true
			memberSet = append(memberSet, tag)
		}
	}
	explicit := false
	for _, tok := range pos {
		switch {
		case tok == "DIRECT":
			add("direct")
			explicit = true
		case groupNames[tok]:
			add(tok) // nested group (its own tag)
			explicit = true
		default:
			if n, ok := nodeByName[tok]; ok {
				add(n.Tag)
				explicit = true
			}
		}
	}
	if v, ok := kv["include-other-group"]; ok {
		for _, gname := range splitFields(v) {
			if groupNames[gname] {
				add(gname)
			}
		}
		explicit = true
	}
	includeAll := truthy(kv["include-all-proxies"])
	if includeAll {
		for _, t := range nodeTags {
			add(t)
		}
	}
	if !explicit && !includeAll {
		if pp := kv["policy-path"]; pp != "" {
			for _, t := range nodeTags {
				add(t)
			}
			notes = append(notes, fmt.Sprintf("组「%s」使用外部策略 policy-path，无法本地解析，已降级为全部节点", gl.name))
		}
	}
	if f := kv["policy-regex-filter"]; f != "" {
		if re, err := regexp.Compile(f); err == nil {
			filtered := memberSet[:0]
			nameByTag := map[string]string{}
			for name, n := range nodeByName {
				nameByTag[n.Tag] = name
			}
			for _, t := range memberSet {
				name := nameByTag[t]
				if t == "direct" {
					continue
				}
				if groupNames[t] || re.MatchString(name) || re.MatchString(t) {
					filtered = append(filtered, t)
				}
			}
			memberSet = filtered
		} else {
			notes = append(notes, fmt.Sprintf("组「%s」的 policy-regex-filter 与 Go 正则不兼容，已忽略筛选", gl.name))
		}
	}
	if len(memberSet) == 0 {
		memberSet = []string{"direct"}
		notes = append(notes, fmt.Sprintf("组「%s」迁移后无可用成员，已回退为仅直连", gl.name))
	}

	gd := &GroupDef{Name: gl.name, Members: memberSet}
	switch typ {
	case "select":
		gd.Kind = "selector"
	case "url-test":
		gd.Kind = "urltest"
		gd.URL = kv["url"]
		gd.Interval = "5m"
		if iv := kv["interval"]; iv != "" {
			if secs := atoi(iv, 0); secs > 0 {
				gd.Interval = fmt.Sprintf("%ds", secs)
			}
		}
		gd.Tolerance = atoi(kv["tolerance"], 50)
	case "smart":
		gd.Kind = "urltest"
		gd.Interval = "5m"
		gd.Tolerance = 50
		notes = append(notes, fmt.Sprintf("组「%s」为 smart 型，sing-box 无对应物，已按 urltest（最低延迟）近似", gl.name))
	case "fallback":
		gd.Kind = "urltest"
		gd.Interval = "5m"
		notes = append(notes, fmt.Sprintf("组「%s」为 fallback 型，已按 urltest 近似", gl.name))
	case "load-balance":
		gd.Kind = "selector"
		notes = append(notes, fmt.Sprintf("组「%s」为 load-balance 型，sing-box 无对应物，已降级为 selector 手动选择", gl.name))
	default:
		return nil, fmt.Sprintf("组类型 %s 暂不支持", typ), nil
	}
	return gd, "", notes
}

// Outbound renders a GroupDef as a sing-box outbound object.
func (g *GroupDef) Outbound() map[string]any {
	members := g.Members
	if len(members) == 0 { // tampered persisted model: never panic
		members = []string{"direct"}
	}
	ob := map[string]any{
		"type":      g.Kind,
		"tag":       g.Name,
		"outbounds": members,
	}
	if g.Kind == "selector" {
		ob["default"] = members[0]
	} else {
		if g.URL != "" {
			ob["url"] = g.URL
		}
		if g.Interval != "" {
			ob["interval"] = g.Interval
		}
		if g.Tolerance > 0 {
			ob["tolerance"] = g.Tolerance
		}
	}
	return ob
}

// ruleConverter converts [Rule] lines one by one.
type ruleConverter struct {
	imp       *Imported
	rep       *Report
	resolve   func(string) (string, bool)
	isReject  func(string) bool
	extraSets map[string]string // mapped URL -> rule_set tag
	finalTag  string
	finalPol  string
}

// mapSurgeRulesURL maps a slynnnn/surge-rules list URL to its
// sing-box source-format counterpart. Returns (sing-box URL, tag,
// ok). Merged sets keep their bare name as tag; service/company
// sets get an sr-<cat>-<name> tag. Every mapped set becomes a
// rule-set definition of the generated config in its own right —
// SakuNet does not overlay any built-in routing of its own when an
// imported config is active.
func mapSurgeRulesURL(u string) (string, string, bool) {
	const prefix = "https://raw.githubusercontent.com/slynnnn/surge-rules/main/rules/"
	if !strings.HasPrefix(u, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(u, prefix) // merged/ai.list | service/netflix.list | company/apple.list | merged/ads.txt
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	cat, file := parts[0], parts[1]
	name := strings.TrimSuffix(strings.TrimSuffix(file, ".list"), ".txt")
	switch cat {
	case "merged":
		return config.SingboxRulesBase + cat + "/" + name + ".json", name, true
	case "service", "company":
		return config.SingboxRulesBase + cat + "/" + name + ".json", "sr-" + cat + "-" + name, true
	}
	return "", "", false
}

func (c *ruleConverter) unmigrated(desc, reason string) {
	c.rep.Unmigrated = append(c.rep.Unmigrated, Unmigrated{Section: "Rule", Desc: desc, Reason: reason})
}

// policyRule builds a route rule for target policy, or records an
// unmigrated entry when the policy cannot be resolved.
func (c *ruleConverter) policyRule(fields map[string]any, policy, desc string) {
	if c.isReject(policy) {
		fields["action"] = "reject"
		c.imp.Rules = append(c.imp.Rules, fields)
		c.rep.RulesOK++
		return
	}
	tag, ok := c.resolve(policy)
	if !ok {
		c.unmigrated(desc, "目标策略「"+policy+"」在导入结果中不存在")
		return
	}
	fields["outbound"] = tag
	c.imp.Rules = append(c.imp.Rules, fields)
	c.rep.RulesOK++
}

// ruleSetRule handles RULE-SET / DOMAIN-SET lines.
func (c *ruleConverter) ruleSetRule(url, policy, desc string) {
	if strings.EqualFold(url, "LAN") {
		c.policyRule(map[string]any{"ip_is_private": true}, policy, desc)
		return
	}
	sbURL, tag, ok := mapSurgeRulesURL(url)
	if !ok {
		c.unmigrated(desc, "外部规则集（非 surge-rules 仓），sing-box 无同源格式，未转换")
		return
	}
	if _, dup := c.extraSets[url]; !dup {
		c.extraSets[url] = tag
		c.imp.ExtraRuleSets = append(c.imp.ExtraRuleSets, config.RemoteRuleSet(tag, sbURL))
	}
	c.policyRule(map[string]any{"rule_set": []string{tag}}, policy, desc)
}

func (c *ruleConverter) convert(line string) {
	fields := splitFields(line)
	if len(fields) == 0 {
		return
	}
	typ := strings.ToUpper(fields[0])
	desc := typ // credential-free description; refined below
	switch typ {
	case "FINAL":
		if len(fields) < 2 {
			c.unmigrated(desc, "FINAL 缺少目标策略")
			return
		}
		pol := fields[1]
		c.finalPol = pol
		if c.isReject(pol) {
			c.finalTag = "" // reject cannot be a route final; builder falls back to the main group
			c.rep.Notes = append(c.rep.Notes, "FINAL 指向 REJECT，sing-box final 不能为 reject，已改用配置内主策略组兜底")
			return
		}
		if tag, ok := c.resolve(pol); ok {
			c.finalTag = tag
			c.rep.RulesOK++
		} else {
			c.unmigrated(desc+" → "+pol, "目标策略在导入结果中不存在，FINAL 未迁移")
		}
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		key := map[string]string{
			"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
		}[typ]
		c.policyRule(map[string]any{key: []string{fields[1]}}, fields[2], desc+" → "+fields[2])
	case "RULE-SET", "DOMAIN-SET":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		host := fields[1]
		if i := strings.Index(fields[1], "://"); i >= 0 {
			host = strings.SplitN(fields[1][i+3:], "/", 2)[0]
		}
		c.ruleSetRule(fields[1], fields[2], desc+"（"+host+"）→ "+fields[2])
	case "IP-CIDR", "IP-CIDR6":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		c.policyRule(map[string]any{"ip_cidr": []string{fields[1]}}, fields[2], desc+" → "+fields[2])
	case "SRC-IP", "SRC-IP-CIDR":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		c.policyRule(map[string]any{"source_ip_cidr": []string{fields[1]}}, fields[2], desc+" → "+fields[2])
	case "DEST-PORT":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		if lo, hi, ok := strings.Cut(fields[1], "-"); ok {
			c.policyRule(map[string]any{"port_range": []string{lo + ":" + hi}}, fields[2], desc+" → "+fields[2])
		} else if p, err := strconv.Atoi(fields[1]); err == nil {
			c.policyRule(map[string]any{"port": []int{p}}, fields[2], desc+" → "+fields[2])
		} else {
			c.unmigrated(desc, "端口格式无法解析")
		}
	case "PROTOCOL":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		p := strings.ToLower(fields[1])
		if p == "tcp" || p == "udp" {
			c.policyRule(map[string]any{"network": []string{p}}, fields[2], desc+" → "+fields[2])
		} else {
			c.unmigrated(desc+" "+fields[1], "协议类型 sing-box 路由无对应字段")
		}
	case "PROCESS-NAME":
		if len(fields) < 3 {
			c.unmigrated(desc, "字段不足")
			return
		}
		c.policyRule(map[string]any{"process_name": []string{fields[1]}}, fields[2], desc+" → "+fields[2])
	case "GEOIP":
		if len(fields) >= 3 {
			desc += " → " + fields[2]
		}
		c.unmigrated(desc, "sing-box 1.14 已移除 geoip 路由字段，需专用 geoip 规则集，未转换")
	case "USER-AGENT":
		if len(fields) >= 3 {
			desc += " → " + fields[2]
		}
		c.unmigrated(desc, "sing-box 路由无 User-Agent 匹配字段")
	case "URL-REGEX":
		c.unmigrated(desc, "URL-REGEX 按完整 URL 匹配，与 sing-box 域名正则语义不同，未转换")
	case "AND", "OR", "NOT":
		c.unmigrated(desc, "逻辑复合规则未转换")
	default:
		c.unmigrated(desc, "规则类型暂不支持")
	}
}
