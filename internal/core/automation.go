package core

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"sakunet/internal/autostart"
	"sakunet/internal/links"
)

// Automation (v1.2): login autostart, scheduled subscription
// refresh, and the persisted record of both for the settings page.
// Software self-update is check-only and lives in internal/updchk
// (the binary is never silently replaced).

// AutomationView is the settings-page view of the automation prefs.
type AutomationView struct {
	AutostartSupported bool   `json:"autostart_supported"`
	Autostart          bool   `json:"autostart"`
	SubURL             string `json:"sub_url"`
	SubEveryH          int    `json:"sub_every_h"`
	SubAuto            bool   `json:"sub_auto"`
	SubLastAt          string `json:"sub_last_at,omitempty"`
	SubLastMsg         string `json:"sub_last_msg,omitempty"`
}

func exePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

// Automation returns the live autostart state (registry truth on
// Windows) plus the subscription schedule.
func (m *Manager) Automation() AutomationView {
	m.mu.Lock()
	p := m.prefs
	m.mu.Unlock()
	v := AutomationView{
		AutostartSupported: autostart.Supported(),
		Autostart:          p.Autostart,
		SubURL:             p.SubURL,
		SubEveryH:          p.SubEveryH,
		SubAuto:            p.SubAuto,
		SubLastMsg:         p.SubLastMsg,
	}
	if on, err := autostart.Enabled(exePath()); err == nil {
		v.Autostart = on
	}
	if !p.SubLastAt.IsZero() {
		v.SubLastAt = p.SubLastAt.Format("2006-01-02 15:04")
	}
	return v
}

// SetAutostart installs/removes the login entry and persists the
// intent alongside it.
func (m *Manager) SetAutostart(on bool) error {
	if err := autostart.Set(on, exePath()); err != nil {
		return err
	}
	m.mu.Lock()
	m.prefs.Autostart = on
	m.mu.Unlock()
	return m.savePrefs()
}

// SetSubscription stores the auto-update schedule. An empty URL
// with auto off clears the schedule.
func (m *Manager) SetSubscription(url string, everyH int, auto bool) error {
	url = strings.TrimSpace(url)
	if auto && url == "" {
		return fmt.Errorf("开启自动更新前先填写订阅 URL")
	}
	if url != "" && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return fmt.Errorf("订阅 URL 只支持 http/https")
	}
	if everyH <= 0 {
		everyH = 24
	}
	if everyH > 24*7 {
		everyH = 24 * 7
	}
	m.mu.Lock()
	m.prefs.SubURL = url
	m.prefs.SubEveryH = everyH
	m.prefs.SubAuto = auto
	m.mu.Unlock()
	return m.savePrefs()
}

// StartBackground launches the periodic subscription updater
// (idempotent). It checks shortly after start (to catch updates
// missed while the app was closed) and then on a slow ticker.
func (m *Manager) StartBackground() {
	m.bgOnce.Do(func() {
		go func() {
			time.Sleep(30 * time.Second)
			m.maybeUpdateSubscription()
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for range t.C {
				m.maybeUpdateSubscription()
			}
		}()
	})
}

func (m *Manager) maybeUpdateSubscription() {
	m.mu.Lock()
	p := m.prefs
	m.mu.Unlock()
	if !p.SubAuto || p.SubURL == "" {
		return
	}
	every := time.Duration(p.SubEveryH) * time.Hour
	if every <= 0 {
		every = 24 * time.Hour
	}
	if !p.SubLastAt.IsZero() && time.Since(p.SubLastAt) < every {
		return
	}
	if err := m.runSubscriptionUpdate(); err != nil {
		m.mu.Lock()
		m.prefs.SubLastAt = time.Now()
		m.prefs.SubLastMsg = "失败：" + err.Error()
		m.mu.Unlock()
		_ = m.savePrefs()
	}
}

// runSubscriptionUpdate fetches the stored subscription URL and
// merges its nodes into the active store (same dedupe semantics
// as a manual link import; nodes removed upstream are not pruned).
func (m *Manager) runSubscriptionUpdate() error {
	m.mu.Lock()
	url := m.prefs.SubURL
	m.mu.Unlock()
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SakuNet subscription-autoupdate")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("拉取订阅失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("拉取订阅失败：HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	nodes, _ := links.ParseSubscription(data)
	added := 0
	if len(nodes) > 0 {
		added, err = m.ImportNodes(nodes)
		if err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.prefs.SubLastAt = time.Now()
	m.prefs.SubLastMsg = fmt.Sprintf("成功：解析 %d 个节点，新增 %d 个", len(nodes), added)
	m.mu.Unlock()
	return m.savePrefs()
}
