package surge

import (
	"encoding/json"
	"os"
	"testing"
)

func TestBuildFixtureTun(t *testing.T) {
	imp := parseFixture(t)
	cfg, err := BuildImportedTun(imp, "rule", true)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg["inbounds"].([]any)
	if len(in) != 2 {
		t.Fatalf("inbounds = %d, want 2 (mixed + tun)", len(in))
	}
	tun := in[1].(map[string]any)
	if tun["type"] != "tun" || tun["auto_route"] != true {
		t.Errorf("tun inbound = %v", tun)
	}
	if out := os.Getenv("SAKUNET_FIXTURE_TUN_OUT"); out != "" {
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
