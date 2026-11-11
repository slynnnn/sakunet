package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBatchDelay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /proxies/<name>/delay
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
		if name == "bad" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"delay": %d}`, 40+len(name))
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := c.BatchDelay(ctx, []string{"alpha", "bad", "beta"}, "http://example.com/204", 5000)
	if got["alpha"] != 45 || got["beta"] != 44 {
		t.Errorf("delays = %v", got)
	}
	if got["bad"] != -1 {
		t.Errorf("failed node must map to -1, got %v", got)
	}
	if len(got) != 3 {
		t.Errorf("result count = %d, want 3", len(got))
	}
}
