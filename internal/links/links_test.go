package links

import (
	"encoding/base64"
	"strings"
	"testing"
)

// All credentials below are dummies and all addresses are TEST-NET-1
// (192.0.2.0/24) or example.com, per RFC 5737 / RFC 2606.

func TestParseSnell(t *testing.T) {
	n, err := ParseLink("snell://192.0.2.10:6080?psk=dummy-psk&version=6&mode=unsafe-raw&obfs=http&obfs-host=example.com#Snell%20Node")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Type != "snell" || n.Server != "192.0.2.10" || n.Port != 6080 {
		t.Errorf("addr = %s %s:%d", n.Type, n.Server, n.Port)
	}
	if n.PSK != "dummy-psk" {
		t.Errorf("PSK = %q", n.PSK)
	}
	if n.Version != 6 || n.Mode != "unsafe-raw" {
		t.Errorf("Version/Mode = %d/%q", n.Version, n.Mode)
	}
	if n.Name != "Snell Node" {
		t.Errorf("Name = %q, want URL-decoded fragment", n.Name)
	}
}

func TestParseSnellDefaultVersion(t *testing.T) {
	// No version parameter: Surge convention is v5.
	n, err := ParseLink("snell://192.0.2.10:6080?psk=dummy-psk")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Version != 5 {
		t.Errorf("Version = %d, want default 5", n.Version)
	}
	if n.Name != "192.0.2.10:6080" {
		t.Errorf("Name = %q, want server:port fallback", n.Name)
	}
}

func TestParseAnyTLS(t *testing.T) {
	n, err := ParseLink("anytls://dummy-pass@192.0.2.11:443?sni=example.com&insecure=1#AnyTLS%20Node")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Type != "anytls" || n.Server != "192.0.2.11" || n.Port != 443 {
		t.Errorf("addr = %s %s:%d", n.Type, n.Server, n.Port)
	}
	if n.Password != "dummy-pass" {
		t.Errorf("Password = %q", n.Password)
	}
	if n.SNI != "example.com" || !n.Insecure {
		t.Errorf("SNI/Insecure = %q/%v", n.SNI, n.Insecure)
	}
	if n.Name != "AnyTLS Node" {
		t.Errorf("Name = %q", n.Name)
	}
}

func TestParseHysteria2(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		n, err := ParseLink(scheme + "://dummy-pass@192.0.2.12:443?sni=example.com&obfs-password=dummy-obfs&insecure=1#Hy2")
		if err != nil {
			t.Fatalf("%s: ParseLink: %v", scheme, err)
		}
		if n.Type != "hysteria2" {
			t.Errorf("%s: Type = %q, want hysteria2", scheme, n.Type)
		}
		if n.Password != "dummy-pass" || n.ObfsPassword != "dummy-obfs" {
			t.Errorf("%s: Password/ObfsPassword = %q/%q", scheme, n.Password, n.ObfsPassword)
		}
		if n.SNI != "example.com" || !n.Insecure {
			t.Errorf("%s: SNI/Insecure = %q/%v", scheme, n.SNI, n.Insecure)
		}
	}
}

func TestParseSS(t *testing.T) {
	sip002Userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:dummy-pass"))
	tests := []struct {
		name         string
		link         string
		method, pass string
		server       string
		port         int
		plugin       string
		pluginOpts   string
		nodeName     string
	}{
		{
			name:   "SIP002 with obfs plugin",
			link:   "ss://" + sip002Userinfo + "@192.0.2.20:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS-SIP002",
			method: "aes-256-gcm", pass: "dummy-pass",
			server: "192.0.2.20", port: 8388,
			plugin: "obfs-local", pluginOpts: "obfs=http;obfs-host=example.com",
			nodeName: "SS-SIP002",
		},
		{
			name: "legacy whole-base64",
			link: "ss://" + base64.StdEncoding.EncodeToString(
				[]byte("aes-128-gcm:dummy-legacy@192.0.2.21:8389")) + "#SS-Legacy",
			method: "aes-128-gcm", pass: "dummy-legacy",
			server: "192.0.2.21", port: 8389,
			nodeName: "SS-Legacy",
		},
		{
			name:   "plaintext userinfo",
			link:   "ss://chacha20-ietf-poly1305:dummy-plain@192.0.2.22:8390#SS-Plain",
			method: "chacha20-ietf-poly1305", pass: "dummy-plain",
			server: "192.0.2.22", port: 8390,
			nodeName: "SS-Plain",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := ParseLink(tc.link)
			if err != nil {
				t.Fatalf("ParseLink: %v", err)
			}
			if n.Type != "shadowsocks" {
				t.Errorf("Type = %q", n.Type)
			}
			if n.Method != tc.method || n.Password != tc.pass {
				t.Errorf("Method/Password = %q/%q, want %q/%q", n.Method, n.Password, tc.method, tc.pass)
			}
			if n.Server != tc.server || n.Port != tc.port {
				t.Errorf("addr = %s:%d, want %s:%d", n.Server, n.Port, tc.server, tc.port)
			}
			if n.Plugin != tc.plugin || n.PluginOpts != tc.pluginOpts {
				t.Errorf("Plugin/PluginOpts = %q/%q, want %q/%q", n.Plugin, n.PluginOpts, tc.plugin, tc.pluginOpts)
			}
			if n.Name != tc.nodeName {
				t.Errorf("Name = %q, want %q", n.Name, tc.nodeName)
			}
		})
	}
}

func TestParseTrojanWS(t *testing.T) {
	n, err := ParseLink("trojan://dummy-pass@192.0.2.13:443?sni=example.com&type=ws&path=%2Fws&host=cdn.example.com#Trojan%20WS")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Type != "trojan" || n.Password != "dummy-pass" {
		t.Errorf("Type/Password = %q/%q", n.Type, n.Password)
	}
	if n.SNI != "example.com" || !n.TLS {
		t.Errorf("SNI/TLS = %q/%v", n.SNI, n.TLS)
	}
	if n.Network != "ws" || n.WSPath != "/ws" || n.WSHost != "cdn.example.com" {
		t.Errorf("transport = %q %q %q", n.Network, n.WSPath, n.WSHost)
	}
	if n.Name != "Trojan WS" {
		t.Errorf("Name = %q", n.Name)
	}
}

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"VMess Node","add":"192.0.2.15","port":"443",` +
		`"id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws",` +
		`"type":"none","host":"cdn.example.com","path":"/vmess","tls":"tls",` +
		`"sni":"example.com","scy":"auto"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	n, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Type != "vmess" || n.Server != "192.0.2.15" || n.Port != 443 {
		t.Errorf("addr = %s %s:%d", n.Type, n.Server, n.Port)
	}
	if n.Name != "VMess Node" {
		t.Errorf("Name = %q, want ps field", n.Name)
	}
	if n.UUID != "11111111-2222-3333-4444-555555555555" || n.AlterID != 0 {
		t.Errorf("UUID/AlterID = %q/%d", n.UUID, n.AlterID)
	}
	if n.Network != "ws" || n.WSPath != "/vmess" || n.WSHost != "cdn.example.com" {
		t.Errorf("transport = %q %q %q", n.Network, n.WSPath, n.WSHost)
	}
	if !n.TLS || n.SNI != "example.com" || n.Security != "auto" {
		t.Errorf("TLS/SNI/Security = %v/%q/%q", n.TLS, n.SNI, n.Security)
	}
}

func TestParseVLESSRealityWS(t *testing.T) {
	n, err := ParseLink("vless://11111111-2222-3333-4444-555555555555@192.0.2.14:443" +
		"?security=reality&pbk=dummy-pbk&sid=abcd&flow=xtls-rprx-vision" +
		"&type=ws&path=%2Fvless&host=cdn.example.com&sni=example.com#VLESS%20Reality")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Type != "vless" || n.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("Type/UUID = %q/%q", n.Type, n.UUID)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", n.Flow)
	}
	if !n.TLS || n.RealityPublicKey != "dummy-pbk" || n.RealityShortID != "abcd" {
		t.Errorf("TLS/Reality = %v/%q/%q", n.TLS, n.RealityPublicKey, n.RealityShortID)
	}
	if n.Network != "ws" || n.WSPath != "/vless" || n.WSHost != "cdn.example.com" {
		t.Errorf("transport = %q %q %q", n.Network, n.WSPath, n.WSHost)
	}
	if n.SNI != "example.com" {
		t.Errorf("SNI = %q", n.SNI)
	}
}

func TestParseVLESSGRPC(t *testing.T) {
	n, err := ParseLink("vless://11111111-2222-3333-4444-555555555555@example.com:443" +
		"?security=tls&type=grpc&serviceName=dummy-svc&sni=example.com#VLESS%20gRPC")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if n.Network != "grpc" || n.ServiceName != "dummy-svc" {
		t.Errorf("transport = %q/%q", n.Network, n.ServiceName)
	}
	if !n.TLS {
		t.Errorf("TLS = false, want true for security=tls")
	}
}

func TestParseLinkErrors(t *testing.T) {
	for _, link := range []string{
		"",
		"not-a-link",
		"unknown://192.0.2.1:1234#x",
		"vless://@192.0.2.1:443#no-uuid",
		"snell://192.0.2.1:6080#no-psk",
		"vmess://!!!not-base64!!!",
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("ParseLink(%q) = nil error, want error", link)
		}
	}
}

func TestParseSubscriptionMixed(t *testing.T) {
	sub := strings.Join([]string{
		"# a comment line",
		"",
		"snell://192.0.2.10:6080?psk=dummy-psk&version=6#Sub%20Snell",
		"trojan://dummy-pass@192.0.2.13:443?sni=example.com#Sub%20Trojan",
		"bogus://whatever",
	}, "\n")
	nodes, errs := ParseSubscription([]byte(sub))
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2: %+v", len(nodes), nodes)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %d, want 1: %v", len(errs), errs)
	}
	if nodes[0].Type != "snell" || nodes[1].Type != "trojan" {
		t.Errorf("types = %q, %q", nodes[0].Type, nodes[1].Type)
	}
}

func TestParseSubscriptionBase64AndDedup(t *testing.T) {
	plain := strings.Join([]string{
		"anytls://dummy-pass@192.0.2.11:443#One",
		"anytls://dummy-pass@192.0.2.11:443#One%20Duplicate",
		"hysteria2://dummy-pass@192.0.2.12:443#Two",
	}, "\n")
	blob := base64.StdEncoding.EncodeToString([]byte(plain))
	nodes, errs := ParseSubscription([]byte(blob))
	if len(errs) != 0 {
		t.Fatalf("errs = %v", errs)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 after dedup", len(nodes))
	}
	if nodes[0].Name != "One" {
		t.Errorf("first occurrence kept: Name = %q, want One", nodes[0].Name)
	}
}
