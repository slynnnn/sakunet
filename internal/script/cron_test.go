package script

import (
	"testing"
	"time"
)

func TestParseCronAndNext(t *testing.T) {
	at := func(s string) time.Time {
		tm, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	cases := []struct {
		expr, from, want string
	}{
		{"*/15 * * * *", "2026-01-05 10:07", "2026-01-05 10:15"},
		{"0 9 * * *", "2026-01-05 10:00", "2026-01-06 09:00"},
		{"0 9 * * 1", "2026-01-05 10:00", "2026-01-12 09:00"},   // Mondays (2026-01-05 is a Monday, but 09:00 passed)
		{"30 8 1 * *", "2026-01-05 10:00", "2026-02-01 08:30"}, // monthly
		{"@daily", "2026-01-05 10:00", "2026-01-06 00:00"},
		{"0 0 29 2 *", "2026-01-05 10:00", "2028-02-29 00:00"}, // leap day
		{"0,30 9-18/3 * * *", "2026-01-05 10:00", "2026-01-05 12:00"},
	}
	for _, c := range cases {
		s, err := parseCron(c.expr)
		if err != nil {
			t.Errorf("%s: %v", c.expr, err)
			continue
		}
		got := s.Next(at(c.from))
		if got.Format("2006-01-02 15:04") != c.want {
			t.Errorf("%s from %s: next = %s, want %s", c.expr, c.from, got.Format("2006-01-02 15:04"), c.want)
		}
	}
	for _, bad := range []string{"", "* * * *", "61 * * * *", "0 25 * * *", "0 0 * * mon", "*/0 * * * *", "0 0 32 1 *"} {
		if _, err := parseCron(bad); err == nil {
			t.Errorf("parseCron(%q) should fail", bad)
		}
	}
}
