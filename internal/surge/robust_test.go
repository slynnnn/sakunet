package surge

import (
	"strings"
	"testing"
)

// Adversarial inputs: the parser must never panic and must always
// produce a readable report/build result.
func TestParseAdversarial(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"only headers":     "[Proxy]\n[Proxy Group]\n[Rule]\n[MITM]\n",
		"truncated proxy":  "[Proxy]\nA = snell, 192.0.2.1",
		"garbage bytes":    "\x00\xff\xfe random \x80\x81\n[Proxy]\n= = =\n",
		"no equals":        "[Proxy]\nhello world\n[Rule]\n???\n",
		"dup sections":     "[Proxy]\nA = direct, 1.1.1.1, 1\n[Proxy]\nB = ss, 192.0.2.2, 8388, encrypt-method=aes-256-gcm, password=x\n",
		"self cycle":       "[Proxy Group]\nA = select, A, DIRECT\n",
		"mutual cycle":     "[Proxy Group]\nA = select, B\nB = select, A, DIRECT\n",
		"group ghost node": "[Proxy Group]\nA = select, NoSuchNode\n",
		"huge rule value":  "[Rule]\nDOMAIN," + strings.Repeat("a", 100000) + ",DIRECT\n",
		"bad regex group":  "[Proxy]\nA = ss, 192.0.2.2, 8388, encrypt-method=aes-256-gcm, password=x\n[Proxy Group]\nG = select, include-all-proxies=true, policy-regex-filter=([bad\n",
		"rewrite garbage":  "[URL Rewrite]\n^([bad https://x 302\nonlyonefield\n\n",
		"mitm no hostname": "[MITM]\nca-p12 = AAAA\nfoo = bar\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked: %v", r)
				}
			}()
			imp, err := Parse("adv.conf", []byte(in))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if imp == nil || imp.Report.Unmigrated == nil {
				t.Fatalf("report not populated: %+v", imp)
			}
			// Building must not panic either, even for empty models.
			_, _ = BuildImported(imp, "rule")
			// Engine compile of preserved garbage must not panic.
			_ = imp.Engine.Compile()
		})
	}
}

func TestGroupCycleBroken(t *testing.T) {
	imp, err := Parse("cycle.conf", []byte(
		"[Proxy Group]\nA = select, B\nB = select, A, DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(imp.Report.Notes, " ")
	if !strings.Contains(notes, "循环引用已断开") {
		t.Errorf("cycle note missing, notes = %v", imp.Report.Notes)
	}
	// Every group member must resolve (no dangling/cyclic edges).
	names := map[string]bool{"direct": true}
	for _, g := range imp.Groups {
		names[g.Name] = true
	}
	for _, g := range imp.Groups {
		for _, m := range g.Members {
			if m == g.Name {
				t.Errorf("group %s still references itself", g.Name)
			}
			if !names[m] {
				t.Errorf("group %s member %q unresolved", g.Name, m)
			}
		}
	}
	if _, err := BuildImported(imp, "rule"); err != nil {
		t.Fatal(err)
	}
}

func TestModuleAdversarial(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseModule panicked: %v", r)
		}
	}()
	mr := ParseModule("bad.sgmodule", []byte("\x00\xff\n[MITM]\nhostname\n=\n[Script]\nnoequals\n[URL Rewrite]\n^\n"))
	_ = mr
}

func TestCompileRuleKinds(t *testing.T) {
	ed := &EngineData{URLRewrites: []RewriteRule{
		{Raw: `^https://a\.com/old https://a.com/new 302`},
		{Raw: `^https://a\.com/ad - reject`},
		{Raw: `^https://a\.com/x - reject-dict`},
		{Raw: `^https://a\.com/ header-set X-Test hello world`},
		{Raw: `^https://a\.com/ response-header-del X-Debug`},
		{Raw: `^https://a\.com/ https://a.com/ some-unknown-kind`},
	}}
	ce := ed.Compile()
	if len(ce.Rules) != 5 || len(ce.Unsupported) != 1 {
		t.Fatalf("rules = %d unsupported = %d, want 5/1 (%v)", len(ce.Rules), len(ce.Unsupported), ce.Unsupported)
	}
	hdr := ce.Rules[3]
	if hdr.Op != OpHeader || hdr.Name != "X-Test" || hdr.Value != "hello world" || hdr.Direction != "request" {
		t.Errorf("header rule = %+v", hdr)
	}
	resp := ce.Rules[4]
	if resp.Direction != "response" || resp.HeaderOp != "del" || resp.Name != "X-Debug" {
		t.Errorf("response header rule = %+v", resp)
	}
}
