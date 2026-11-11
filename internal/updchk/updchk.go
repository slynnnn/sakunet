// Package updchk checks GitHub Releases for a newer SakuNet
// version. It only reports: downloading and replacing the binary
// is always a manual step for the user (no silent self-replace).
package updchk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIBase is the releases endpoint (a variable so tests can point
// it at a local server).
var APIBase = "https://api.github.com/repos/slynnnn/sakunet/releases/latest"

// Info is one update-check result.
type Info struct {
	Current  string `json:"current"`
	Latest   string `json:"latest,omitempty"`
	Update   bool   `json:"update"` // Latest is strictly newer
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Checked  string `json:"checked"` // RFC3339
	Error    string `json:"error,omitempty"`
}

// Latest fetches the newest release tag and compares it with
// current (both "vX.Y[.Z]" shaped; comparison is numeric per
// component, anything unparsable compares as older-or-equal).
func Latest(current string, client *http.Client) Info {
	info := Info{Current: current, Checked: time.Now().Format(time.RFC3339)}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, APIBase, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SakuNet update-check")
	resp, err := client.Do(req)
	if err != nil {
		info.Error = "检查更新失败：" + err.Error()
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("检查更新失败：HTTP %d", resp.StatusCode)
		return info
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		info.Error = "检查更新失败：响应无法解析"
		return info
	}
	info.Latest = rel.TagName
	info.URL = rel.HTMLURL
	info.Notes = rel.Name
	info.Update = Newer(rel.TagName, current)
	return info
}

// Newer reports whether tag a is a strictly newer version than b.
func Newer(a, b string) bool {
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parse(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	for i, part := range strings.SplitN(v, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(part))
		out[i] = n
	}
	return out
}
