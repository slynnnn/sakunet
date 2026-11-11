package script

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Minimal 5-field cron (minute hour day-of-month month
// day-of-week) as used by Surge's cronexpr parameter, plus the
// common @descriptors. Each field supports *, */n, a, a-b, a-b/n
// and comma lists of those. Day-of-week: 0-7 (0 and 7 = Sunday).
// When both dom and dow are restricted, standard cron semantics
// apply (either match fires).

type cronSchedule struct {
	min, hour, dom, mon, dow map[int]bool
	domAny, dowAny           bool
	expr                     string
}

var cronDescriptors = map[string]string{
	"@hourly":   "0 * * * *",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@weekly":   "0 0 * * 0",
	"@monthly":  "0 0 1 * *",
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
}

func parseCronField(spec string, lo, hi int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("空字段段")
		}
		base, step := part, 1
		if i := strings.Index(part, "/"); i >= 0 {
			base = part[:i]
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("步长 %q 无法解析", part[i+1:])
			}
			step = n
		}
		var from, to int
		switch {
		case base == "*":
			from, to = lo, hi
		case strings.Contains(base, "-"):
			ab := strings.SplitN(base, "-", 2)
			var err error
			if from, err = strconv.Atoi(ab[0]); err != nil {
				return nil, fmt.Errorf("范围 %q 无法解析", base)
			}
			if to, err = strconv.Atoi(ab[1]); err != nil {
				return nil, fmt.Errorf("范围 %q 无法解析", base)
			}
		default:
			v, err := strconv.Atoi(base)
			if err != nil {
				return nil, fmt.Errorf("值 %q 无法解析", base)
			}
			from, to = v, v
		}
		if from < lo || to > hi || from > to {
			return nil, fmt.Errorf("值域 %d-%d 超出 %d-%d", from, to, lo, hi)
		}
		for v := from; v <= to; v += step {
			out[v] = true
		}
	}
	return out, nil
}

// parseCron parses a cronexpr into a schedule.
func parseCron(expr string) (*cronSchedule, error) {
	expr = strings.TrimSpace(expr)
	if d, ok := cronDescriptors[strings.ToLower(expr)]; ok {
		expr = d
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("cronexpr 需要 5 个字段（分 时 日 月 周），得到 %d", len(f))
	}
	s := &cronSchedule{expr: expr}
	var err error
	if s.min, err = parseCronField(f[0], 0, 59); err != nil {
		return nil, fmt.Errorf("分钟字段：%w", err)
	}
	if s.hour, err = parseCronField(f[1], 0, 23); err != nil {
		return nil, fmt.Errorf("小时字段：%w", err)
	}
	if s.dom, err = parseCronField(f[2], 1, 31); err != nil {
		return nil, fmt.Errorf("日字段：%w", err)
	}
	if s.mon, err = parseCronField(f[3], 1, 12); err != nil {
		return nil, fmt.Errorf("月字段：%w", err)
	}
	dowRaw, err := parseCronField(f[4], 0, 7)
	if err != nil {
		return nil, fmt.Errorf("周字段：%w", err)
	}
	s.dow = map[int]bool{}
	for v := range dowRaw {
		s.dow[v%7] = true // 7 -> Sunday (0)
	}
	s.domAny = f[2] == "*"
	s.dowAny = f[4] == "*"
	return s, nil
}

func (s *cronSchedule) matches(t time.Time) bool {
	return s.min[t.Minute()] && s.hour[t.Hour()] && s.mon[int(t.Month())] && s.dayMatches(t)
}

// Next returns the first fire time strictly after t (minute
// granularity), searching at most ~5 years ahead (leap-day
// schedules need the range). The scan skips whole months / days /
// hours whose field cannot match, so far-future schedules stay
// cheap.
func (s *cronSchedule) Next(t time.Time) time.Time {
	cand := t.Truncate(time.Minute).Add(time.Minute)
	limit := cand.Add(5 * 366 * 24 * time.Hour)
	for cand.Before(limit) {
		if !s.mon[int(cand.Month())] {
			cand = time.Date(cand.Year(), cand.Month()+1, 1, 0, 0, 0, 0, cand.Location())
			continue
		}
		if !s.dayMatches(cand) {
			cand = time.Date(cand.Year(), cand.Month(), cand.Day()+1, 0, 0, 0, 0, cand.Location())
			continue
		}
		if !s.hour[cand.Hour()] {
			cand = cand.Truncate(time.Hour).Add(time.Hour)
			continue
		}
		if !s.min[cand.Minute()] {
			cand = cand.Add(time.Minute)
			continue
		}
		return cand
	}
	return time.Time{}
}

// dayMatches applies the dom/dow rule for one calendar day.
func (s *cronSchedule) dayMatches(t time.Time) bool {
	domHit := s.dom[t.Day()]
	dowHit := s.dow[int(t.Weekday())]
	switch {
	case s.domAny && s.dowAny:
		return true
	case s.domAny:
		return dowHit
	case s.dowAny:
		return domHit
	default:
		return domHit || dowHit
	}
}
