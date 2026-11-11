package surge

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Text rule-set resolution. A RULE-SET/DOMAIN-SET line whose URL
// serves a plain-text Surge/Clash list cannot be handed to
// sing-box as a remote rule-set (it only speaks its own source
// JSON / .srs binary formats). Resolution therefore happens once,
// at import time, mirroring ResolveScripts: fetch the list, parse
// the classical entries, and embed the result as an inline
// rule-set definition. Failures are reported per reference: the
// referencing rules are dropped (a dangling rule_set tag would
// fail sing-box check) and an Unmigrated entry records why.
//
// Snapshot semantics: unlike .json/.srs references (true remote
// rule-sets that sing-box refreshes itself), a converted text list
// is a snapshot of import day. Re-importing the config refreshes
// it; the import report says so.

const (
	maxTextSetBytes   = 8 << 20 // per-list download cap
	maxTextSetEntries = 200_000 // per-list converted-entry cap
)

// fetchTextSet is the download seam (unit tests substitute it).
var fetchTextSet = downloadTextSet

func downloadTextSet(rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: scriptDLTimeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SakuNet ruleset-import")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTextSetBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTextSetBytes {
		return nil, fmt.Errorf("规则集超过 %d 字节上限", maxTextSetBytes)
	}
	return body, nil
}

// ResolveRuleSets fetches and converts every pending text
// rule-set reference on the import. Returns human-readable notes
// for the import report (one per resolved or failed reference).
func (imp *Imported) ResolveRuleSets() []string {
	if len(imp.PendingTextSets) == 0 {
		return nil
	}
	var notes []string
	pending := imp.PendingTextSets
	imp.PendingTextSets = nil
	for _, ref := range pending {
		body, err := fetchTextSet(ref.URL)
		if err == nil {
			var def map[string]any
			var stats textSetStats
			def, stats, err = convertTextSet(ref.Tag, body)
			if err == nil {
				imp.ExtraRuleSets = append(imp.ExtraRuleSets, def)
				notes = append(notes, fmt.Sprintf(
					"规则集「%s」已抓取并转换（%d 条：域名 %d / 后缀 %d / 关键词 %d / IP %d，跳过 %d 条无对应类型）——文本集为导入时快照，重新导入可刷新",
					ref.Desc, stats.total(), stats.domain, stats.suffix, stats.keyword, stats.ipcidr, stats.skipped))
				continue
			}
		}
		// Failure: drop every rule that referenced this tag and
		// record the loss in the report instead of failing check.
		dropped := imp.dropRulesForSet(ref.Tag)
		imp.Report.RulesOK -= dropped
		imp.Report.Unmigrated = append(imp.Report.Unmigrated, Unmigrated{
			Section: "Rule",
			Desc:    ref.Desc,
			Reason:  "文本规则集拉取/转换失败：" + err.Error(),
		})
		notes = append(notes, fmt.Sprintf("规则集「%s」拉取失败，已剔除引用它的 %d 条规则：%v", ref.Desc, dropped, err))
	}
	return notes
}

// dropRulesForSet removes route rules whose rule_set list contains
// tag. Returns how many rules were removed.
func (imp *Imported) dropRulesForSet(tag string) int {
	kept := imp.Rules[:0]
	dropped := 0
	for _, r := range imp.Rules {
		if ruleSetRefs(r, tag) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	// Clear the tail so dropped maps are not retained.
	for i := len(kept); i < len(imp.Rules); i++ {
		imp.Rules[i] = nil
	}
	imp.Rules = kept
	return dropped
}

func ruleSetRefs(rule map[string]any, tag string) bool {
	switch v := rule["rule_set"].(type) {
	case []string:
		for _, t := range v {
			if t == tag {
				return true
			}
		}
	case []any:
		for _, t := range v {
			if s, ok := t.(string); ok && s == tag {
				return true
			}
		}
	}
	return false
}

type textSetStats struct {
	domain, suffix, keyword, ipcidr, skipped int
}

func (s textSetStats) total() int { return s.domain + s.suffix + s.keyword + s.ipcidr }

// convertTextSet parses a classical-format list body into an
// inline rule-set definition. Entry types with no sing-box
// headless-rule equivalent are counted as skipped, never guessed.
func convertTextSet(tag string, body []byte) (map[string]any, textSetStats, error) {
	var st textSetStats
	domains := []string{}
	suffixes := []string{}
	keywords := []string{}
	cidrs := []string{}
	seenD := map[string]bool{}
	seenS := map[string]bool{}
	seenK := map[string]bool{}
	seenC := map[string]bool{}
	add := func(dst *[]string, seen map[string]bool, v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			*dst = append(*dst, v)
		}
	}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := splitFields(line)
		if len(fields) == 1 {
			// DOMAIN-SET style bare domain: suffix semantics,
			// with an optional leading dot to strip.
			add(&suffixes, seenS, strings.TrimPrefix(fields[0], "."))
			st.suffix++
			continue
		}
		typ := strings.ToUpper(fields[0])
		val := fields[1]
		switch typ {
		case "DOMAIN":
			add(&domains, seenD, val)
			st.domain++
		case "DOMAIN-SUFFIX":
			add(&suffixes, seenS, strings.TrimPrefix(val, "."))
			st.suffix++
		case "DOMAIN-KEYWORD":
			add(&keywords, seenK, val)
			st.keyword++
		case "IP-CIDR", "IP-CIDR6":
			add(&cidrs, seenC, val)
			st.ipcidr++
		default:
			st.skipped++
		}
		if st.total() > maxTextSetEntries {
			return nil, st, fmt.Errorf("条目超过 %d 上限", maxTextSetEntries)
		}
	}
	if st.total() == 0 {
		return nil, st, fmt.Errorf("列表中没有可转换的条目（跳过 %d 条）", st.skipped)
	}
	rules := []any{}
	if len(domains) > 0 {
		rules = append(rules, map[string]any{"domain": domains})
	}
	if len(suffixes) > 0 {
		rules = append(rules, map[string]any{"domain_suffix": suffixes})
	}
	if len(keywords) > 0 {
		rules = append(rules, map[string]any{"domain_keyword": keywords})
	}
	if len(cidrs) > 0 {
		rules = append(rules, map[string]any{"ip_cidr": cidrs})
	}
	return map[string]any{"type": "inline", "tag": tag, "rules": rules}, st, nil
}
