package surge

import (
	"strings"
	"testing"
)

func TestCompileBodyRules(t *testing.T) {
	ed := &EngineData{URLRewrites: []RewriteRule{
		{Raw: `^https://api\.example\.com/ response-body "ad":"[^"]*" "ad":""`},
		{Raw: `^https://api\.example\.com/ request-body secret=\w+ secret=REDACTED`},
		{Raw: `^https://api\.example\.com/ response-body "track":\d+ `},
		{Raw: `^https://api\.example\.com/ response-body ([a-z]+ broken`},
		{Raw: `^https://api\.example\.com/ response-body`},
	}}
	ce := ed.Compile()
	if len(ce.Rules) != 3 {
		t.Fatalf("compiled = %d, want 3 (%v)", len(ce.Rules), ce.Unsupported)
	}
	if len(ce.Unsupported) != 2 {
		t.Fatalf("unsupported = %v, want 2", ce.Unsupported)
	}
	resp := ce.Rules[0]
	if resp.Op != OpBody || resp.Direction != "response" {
		t.Errorf("rule 0 = %s/%s", resp.Op, resp.Direction)
	}
	got := string(resp.ApplyBody([]byte(`{"ad":"BUY-NOW","keep":1}`)))
	if got != `{"ad":"","keep":1}` {
		t.Errorf("response replace = %s", got)
	}
	req := ce.Rules[1]
	if req.Direction != "request" || string(req.ApplyBody([]byte("a=1&secret=abc123"))) != "a=1&secret=REDACTED" {
		t.Errorf("request replace wrong: %q", req.ApplyBody([]byte("a=1&secret=abc123")))
	}
	del := ce.Rules[2]
	if out := string(del.ApplyBody([]byte(`{"track":42,"x":1}`))); !strings.Contains(out, `"x":1`) || strings.Contains(out, "track") {
		t.Errorf("delete-form replace = %s", out)
	}
}
