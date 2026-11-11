package updchk

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.2", "v1.1", true},
		{"v1.2.1", "v1.2", true},
		{"v1.2", "v1.2", false},
		{"v1.1", "v1.2", false},
		{"v2.0", "v1.9.9", true},
		{"v1.10", "v1.9", true},
		{"garbage", "v1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestLatestAgainstServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v1.3","html_url":"https://example.com/rel/v1.3","name":"SakuNet v1.3"}`)
	}))
	defer srv.Close()
	old := APIBase
	APIBase = srv.URL
	defer func() { APIBase = old }()
	info := Latest("v1.2", srv.Client())
	if info.Error != "" || !info.Update || info.Latest != "v1.3" || info.URL == "" {
		t.Errorf("info = %+v", info)
	}
	info = Latest("v1.3", srv.Client())
	if info.Update {
		t.Errorf("same version must not flag update: %+v", info)
	}
}
