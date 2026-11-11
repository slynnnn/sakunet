// Package links parses proxy share links (snell://, anytls://,
// hysteria2://, ss://, trojan://, vmess://, vless://, plus http(s)://
// and socks5:// userinfo links) into config.Node values, and parses
// whole subscription payloads (plain multi-line text or a single
// base64 blob) into a deduplicated node list.
//
// Every parse targets the fields of internal/config's Node struct;
// nothing here touches sing-box config generation — that stays in
// config.OutboundFor / config.Build.
package links

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"sakunet/internal/config"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// decodeBase64 tolerates every dialect found in the wild: standard or
// URL-safe alphabet, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64 input")
	}
	encs := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encs {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if rem := len(s) % 4; rem != 0 {
		padded := s + strings.Repeat("=", 4-rem)
		for _, enc := range encs {
			if b, err := enc.DecodeString(padded); err == nil {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("invalid base64 %q", truncate(s, 24))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// qGet returns the first non-empty query value among keys (query keys
// differ in casing/spelling between generators).
func qGet(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// qBool parses 1/true/yes/on and 0/false/no/off style query flags.
// It reports (value, present).
func qBool(q url.Values, keys ...string) (bool, bool) {
	for _, k := range keys {
		v, ok := q[k]
		if !ok || len(v) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v[0])) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off", "":
			return false, true
		}
	}
	return false, false
}

func parseInsecure(q url.Values) bool {
	v, _ := qBool(q, "insecure", "allowInsecure", "allow_insecure", "skip-cert-verify")
	return v
}

// credentialFromUserinfo extracts a password-only userinfo:
// "password@host" yields the username segment; "user:password@host"
// yields the password segment.
func credentialFromUserinfo(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		return pw
	}
	return u.User.Username()
}

// finish applies the shared invariants: name fallback and Tag = Name.
func finish(n *config.Node, fragment string) *config.Node {
	name := strings.TrimSpace(fragment)
	if name == "" {
		name = n.Name // e.g. vmess "ps"
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", n.Server, n.Port)
	}
	n.Name = name
	n.Tag = name
	return n
}

// hostPort validates server/port from a parsed URL.
func hostPort(u *url.URL, n *config.Node) error {
	n.Server = u.Hostname()
	if n.Server == "" {
		return fmt.Errorf("missing server host")
	}
	p := u.Port()
	if p == "" {
		return fmt.Errorf("missing port for server %q", n.Server)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	n.Port = port
	return nil
}

// applyTransport maps a type/path/host/serviceName query quartet onto
// the Node transport fields. Only ws and grpc exist in config.Node;
// a ws-looking path/host without an explicit type is taken as ws.
func applyTransport(n *config.Node, q url.Values) {
	typ := strings.ToLower(qGet(q, "type", "net", "network"))
	path := qGet(q, "path")
	host := qGet(q, "host")
	switch typ {
	case "ws", "websocket":
		n.Network = "ws"
	case "grpc":
		n.Network = "grpc"
	case "", "tcp", "raw":
		if path != "" || host != "" {
			n.Network = "ws"
		}
	default:
		// kcp/h2/quic etc. have no config.Node representation; leave
		// Network empty rather than emit a transport outbound()
		// would silently drop.
		return
	}
	switch n.Network {
	case "ws":
		n.WSPath = path
		n.WSHost = host
	case "grpc":
		n.ServiceName = qGet(q, "serviceName", "service_name", "servicename")
		if n.ServiceName == "" {
			// Some generators carry the gRPC service name in path.
			n.ServiceName = strings.Trim(path, "/")
		}
	}
}

// ---------------------------------------------------------------------------
// ParseLink
// ---------------------------------------------------------------------------

// ParseLink parses one share link into a config.Node.
//
// Supported schemes: snell, anytls, hysteria2 (alias hy2), ss,
// trojan, vmess, vless, http, https, socks, socks5.
// The node name comes from the #fragment (URL-decoded); when it is
// absent the name falls back to "server:port" (vmess uses its "ps"
// field first).
func ParseLink(line string) (*config.Node, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty link")
	}
	scheme, _, found := strings.Cut(line, "://")
	if !found {
		return nil, fmt.Errorf("not a share link (no scheme): %q", truncate(line, 32))
	}
	switch strings.ToLower(scheme) {
	case "snell":
		return parseSnell(line)
	case "anytls":
		return parseAnyTLS(line)
	case "hysteria2", "hy2":
		return parseHysteria2(line)
	case "ss":
		return parseSS(line)
	case "trojan":
		return parseTrojan(line)
	case "vmess":
		return parseVMess(line)
	case "vless":
		return parseVLESS(line)
	case "http", "https":
		return parseHTTP(line, strings.ToLower(scheme) == "https")
	case "socks", "socks5":
		return parseSOCKS(line)
	default:
		return nil, fmt.Errorf("unsupported link scheme %q", scheme)
	}
}

// parseURLLink is the common front-end for the url.URL-shaped schemes.
func parseURLLink(line, typ string) (*config.Node, *url.URL, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s link: %w", typ, err)
	}
	n := &config.Node{Type: typ}
	if err := hostPort(u, n); err != nil {
		return nil, nil, fmt.Errorf("%s link: %w", typ, err)
	}
	return n, u, nil
}

// ---------------------------------------------------------------------------
// snell
// ---------------------------------------------------------------------------

// snell://server:port?psk=xxx&version=6&mode=default#name
// Unrelated Surge parameters (obfs, obfs-host, udp-relay, ...) are
// ignored — config.Node has no fields for them.
func parseSnell(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "snell")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	n.PSK = q.Get("psk")
	if n.PSK == "" {
		n.PSK = credentialFromUserinfo(u)
	}
	if n.PSK == "" {
		return nil, fmt.Errorf("snell link: missing psk")
	}
	// Version: Surge snell links without an explicit version are v5
	// servers (the Surge default), so the default here is 5, not 6.
	n.Version = 5
	if v := q.Get("version"); v != "" {
		ver, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("snell link: invalid version %q", v)
		}
		n.Version = ver
	}
	n.Mode = q.Get("mode")
	if v, ok := qBool(q, "tfo"); ok {
		n.TFO = v
	}
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// anytls
// ---------------------------------------------------------------------------

// anytls://password@server:port?sni=&insecure=1#name
func parseAnyTLS(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "anytls")
	if err != nil {
		return nil, err
	}
	n.Password = credentialFromUserinfo(u)
	if n.Password == "" {
		return nil, fmt.Errorf("anytls link: missing password")
	}
	q := u.Query()
	n.SNI = qGet(q, "sni", "peer")
	n.Insecure = parseInsecure(q)
	n.TLS = true // anytls is TLS by definition; outbound() always emits it
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// hysteria2
// ---------------------------------------------------------------------------

// hysteria2://password@server:port?sni=&obfs-password=&insecure=#name
// hy2:// is an alias for the same shape.
func parseHysteria2(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "hysteria2")
	if err != nil {
		return nil, err
	}
	n.Password = credentialFromUserinfo(u)
	if n.Password == "" {
		return nil, fmt.Errorf("hysteria2 link: missing password")
	}
	q := u.Query()
	n.SNI = qGet(q, "sni", "peer")
	n.ObfsPassword = qGet(q, "obfs-password", "obfs_password", "obfsPassword")
	n.Insecure = parseInsecure(q)
	n.TLS = true // hysteria2 runs over TLS/QUIC; outbound() always emits it
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// shadowsocks
// ---------------------------------------------------------------------------

// ss:// links come in three shapes:
//
//	SIP002:        ss://base64(method:password)@host:port?plugin=...#name
//	plaintext:     ss://method:password@host:port#name
//	legacy whole:  ss://base64(method:password@host:port)#name
//
// The SIP002 plugin parameter ("obfs-local;obfs=http;obfs-host=x") is
// split into Plugin ("obfs-local") and PluginOpts ("obfs=http;obfs-host=x").
func parseSS(line string) (*config.Node, error) {
	// Split the fragment by hand: url.Parse would misread the legacy
	// whole-base64 shape.
	rest := line
	fragment := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment = rest[i+1:]
		rest = rest[:i]
		if dec, err := url.PathUnescape(fragment); err == nil {
			fragment = dec
		}
	}
	body := rest[strings.Index(rest, "://")+3:]

	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query = body[i+1:]
		body = body[:i]
	}
	q, _ := url.ParseQuery(query)

	var method, password, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo, hostportRaw := body[:at], body[at+1:]
		hostport = strings.TrimSuffix(hostportRaw, "/")
		if dec, err := url.PathUnescape(userinfo); err == nil {
			userinfo = dec
		}
		if i := strings.Index(userinfo, ":"); i >= 0 {
			// Plaintext userinfo. (A base64 blob never contains ':'.)
			method, password = userinfo[:i], userinfo[i+1:]
		} else {
			// SIP002 base64 userinfo.
			raw, err := decodeBase64(userinfo)
			if err != nil {
				return nil, fmt.Errorf("ss link: bad SIP002 userinfo: %w", err)
			}
			cred := string(raw)
			i := strings.Index(cred, ":")
			if i < 0 {
				return nil, fmt.Errorf("ss link: SIP002 userinfo has no method:password separator")
			}
			method, password = cred[:i], cred[i+1:]
		}
	} else {
		// Legacy whole-base64: base64("method:password@host:port").
		// ('@' is outside the base64 alphabet, so no '@' above means
		// the entire body is the blob.)
		raw, err := decodeBase64(body)
		if err != nil {
			return nil, fmt.Errorf("ss link: bad legacy base64 body: %w", err)
		}
		decoded := string(raw)
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return nil, fmt.Errorf("ss link: legacy body has no @host part")
		}
		cred, hp := decoded[:at], decoded[at+1:]
		i := strings.Index(cred, ":")
		if i < 0 {
			return nil, fmt.Errorf("ss link: legacy body has no method:password separator")
		}
		method, password, hostport = cred[:i], cred[i+1:], hp
	}

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// Tolerate a bare "host:port" that SplitHostPort rejects only
		// for a missing bracket etc. by splitting on the last colon.
		i := strings.LastIndex(hostport, ":")
		if i < 0 {
			return nil, fmt.Errorf("ss link: bad host:port %q", hostport)
		}
		host, portStr = hostport[:i], hostport[i+1:]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("ss link: invalid port %q", portStr)
	}
	if method == "" {
		return nil, fmt.Errorf("ss link: missing method")
	}

	n := &config.Node{
		Type:     "shadowsocks",
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
	}
	if plugin := q.Get("plugin"); plugin != "" {
		if i := strings.Index(plugin, ";"); i >= 0 {
			n.Plugin = plugin[:i]
			n.PluginOpts = plugin[i+1:]
		} else {
			n.Plugin = plugin
		}
	}
	return finish(n, fragment), nil
}

// ---------------------------------------------------------------------------
// trojan
// ---------------------------------------------------------------------------

// trojan://password@server:port?sni=&type=ws&path=&host=#name
func parseTrojan(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "trojan")
	if err != nil {
		return nil, err
	}
	n.Password = credentialFromUserinfo(u)
	if n.Password == "" {
		return nil, fmt.Errorf("trojan link: missing password")
	}
	q := u.Query()
	n.SNI = qGet(q, "sni", "peer")
	n.Insecure = parseInsecure(q)
	// Trojan is TLS by definition (outbound() always emits a TLS
	// block); only an explicit security=none turns it off.
	n.TLS = !strings.EqualFold(q.Get("security"), "none")
	applyTransport(n, q)
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// vmess
// ---------------------------------------------------------------------------

// flexInt accepts a JSON number or a quoted numeric string — vmess
// generators disagree on which one "port"/"aid" are.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("vmess: invalid integer %q", s)
	}
	*f = flexInt(v)
	return nil
}

type vmessJSON struct {
	V           string  `json:"v"`
	Ps          string  `json:"ps"`
	Add         string  `json:"add"`
	Port        flexInt `json:"port"`
	ID          string  `json:"id"`
	Aid         flexInt `json:"aid"`
	Net         string  `json:"net"`
	Type        string  `json:"type"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	TLS         string  `json:"tls"`
	SNI         string  `json:"sni"`
	Scy         string  `json:"scy"`
	Security    string  `json:"security"`
	ServiceName string  `json:"serviceName"`
}

// vmess://base64(JSON) with the usual v/ps/add/port/id/aid/net/type/
// host/path/tls/sni fields.
func parseVMess(line string) (*config.Node, error) {
	body := line[strings.Index(line, "://")+3:]
	fragment := ""
	if i := strings.Index(body, "#"); i >= 0 {
		fragment = body[i+1:]
		body = body[:i]
		if dec, err := url.PathUnescape(fragment); err == nil {
			fragment = dec
		}
	}
	raw, err := decodeBase64(body)
	if err != nil {
		return nil, fmt.Errorf("vmess link: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("vmess link: bad JSON payload: %w", err)
	}
	if v.Add == "" {
		return nil, fmt.Errorf("vmess link: missing add (server)")
	}
	if v.ID == "" {
		return nil, fmt.Errorf("vmess link: missing id (uuid)")
	}
	if v.Port == 0 {
		return nil, fmt.Errorf("vmess link: missing port")
	}
	n := &config.Node{
		Type:     "vmess",
		Name:     v.Ps,
		Server:   v.Add,
		Port:     int(v.Port),
		UUID:     v.ID,
		AlterID:  int(v.Aid),
		Security: v.Scy,
		SNI:      v.SNI,
	}
	if n.Security == "" {
		n.Security = v.Security
	}
	if strings.EqualFold(v.TLS, "tls") || strings.EqualFold(v.TLS, "reality") {
		n.TLS = true
	}
	// net/host/path reuse the shared transport mapping; synthesise a
	// query so ws and grpc get identical treatment to the URL schemes.
	q := url.Values{}
	q.Set("type", v.Net)
	q.Set("path", v.Path)
	q.Set("host", v.Host)
	if v.ServiceName != "" {
		q.Set("serviceName", v.ServiceName)
	}
	applyTransport(n, q)
	if fragment != "" && n.Name == "" {
		n.Name = fragment
	}
	return finish(n, fragment), nil
}

// ---------------------------------------------------------------------------
// vless
// ---------------------------------------------------------------------------

// vless://uuid@server:port?security=reality&pbk=&sid=&flow=
// &type=ws/grpc&path=&host=&serviceName=&sni=#name
func parseVLESS(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "vless")
	if err != nil {
		return nil, err
	}
	n.UUID = credentialFromUserinfo(u)
	if n.UUID == "" {
		return nil, fmt.Errorf("vless link: missing uuid")
	}
	q := u.Query()
	n.Flow = q.Get("flow")
	n.SNI = qGet(q, "sni", "peer")
	n.Insecure = parseInsecure(q)
	switch strings.ToLower(q.Get("security")) {
	case "reality":
		n.TLS = true
		n.RealityPublicKey = qGet(q, "pbk", "publicKey", "public-key")
		n.RealityShortID = qGet(q, "sid", "shortId", "short-id")
	case "tls":
		n.TLS = true
	case "none", "":
		// plain or transport-only; TLS stays off unless reality/tls.
	default:
		// Unknown security values (xtls, ...) still imply TLS.
		n.TLS = true
	}
	if n.RealityPublicKey == "" {
		// pbk/sid sometimes appear without security=reality.
		n.RealityPublicKey = qGet(q, "pbk", "publicKey", "public-key")
		n.RealityShortID = qGet(q, "sid", "shortId", "short-id")
		if n.RealityPublicKey != "" {
			n.TLS = true
		}
	}
	applyTransport(n, q)
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// http / socks (bonus: completes the config.Type switch)
// ---------------------------------------------------------------------------

// http://user:pass@server:port#name — https:// flips TLS on.
func parseHTTP(line string, tls bool) (*config.Node, error) {
	n, u, err := parseURLLink(line, "http")
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		n.Username = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	q := u.Query()
	n.SNI = qGet(q, "sni", "peer")
	n.Insecure = parseInsecure(q)
	n.TLS = tls
	return finish(n, u.Fragment), nil
}

// socks5://user:pass@server:port#name
func parseSOCKS(line string) (*config.Node, error) {
	n, u, err := parseURLLink(line, "socks")
	if err != nil {
		return nil, err
	}
	if u.User != nil {
		n.Username = u.User.Username()
		n.Password, _ = u.User.Password()
	}
	return finish(n, u.Fragment), nil
}

// ---------------------------------------------------------------------------
// ParseSubscription
// ---------------------------------------------------------------------------

// ParseSubscription parses a subscription payload into nodes.
//
// The payload may be plain multi-line text (one link per line) or a
// single whole-blob base64 encoding of such text. Blank lines and
// comment lines (starting with '#' or "//") are skipped. A malformed
// line does not abort the parse: it is collected into errs (with its
// 1-based line number) and parsing continues. Duplicate nodes — same
// type, server, port and credential — are deduplicated, keeping the
// first occurrence.
func ParseSubscription(data []byte) (nodes []*config.Node, errs []error) {
	text := maybeDecodeSubscription(data)
	seen := make(map[string]bool)
	for i, raw := range strings.Split(string(text), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		n, err := ParseLink(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		key := dedupKey(n)
		if seen[key] {
			continue
		}
		seen[key] = true
		nodes = append(nodes, n)
	}
	return nodes, errs
}

// maybeDecodeSubscription unwraps a whole-blob base64 subscription.
// Plain text is recognised by containing "://" and returned as-is;
// anything else is tried as base64 (whitespace-insensitive) and used
// only if the decoded bytes look like links.
func maybeDecodeSubscription(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Contains(trimmed, []byte("://")) {
		return data
	}
	compact := bytes.Join(bytes.Fields(trimmed), nil)
	for _, c := range compact {
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_' || c == '='
		if !ok {
			return data
		}
	}
	decoded, err := decodeBase64(string(compact))
	if err != nil || !bytes.Contains(decoded, []byte("://")) {
		return data
	}
	return decoded
}

// dedupKey identifies a node by type + server + port + credential,
// per the subscription dedup rule.
func dedupKey(n *config.Node) string {
	var cred string
	switch n.Type {
	case "snell":
		cred = n.PSK
	case "vless", "vmess":
		cred = n.UUID
	case "shadowsocks":
		cred = n.Method + ":" + n.Password
	default:
		cred = n.Username + ":" + n.Password
	}
	return strings.Join([]string{
		n.Type,
		strings.ToLower(n.Server),
		strconv.Itoa(n.Port),
		cred,
	}, "\x00")
}
