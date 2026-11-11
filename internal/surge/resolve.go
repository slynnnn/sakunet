package surge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Script source resolution. A [Script] entry names its body via
// script-path, which is either a remote URL (the common case for
// shared ad-blocking scripts) or a local file path. Resolution
// happens once, at panel import time: remote bodies are downloaded
// and cached inside imported.json together with their SHA-256, so
// the JS engine never touches the network per request. Every
// failure is recorded on the definition itself (LoadError) and
// summarised in the returned notes — nothing fails silently.

const (
	maxScriptBytes  = 2 << 20 // 2 MiB per script body
	scriptDLTimeout = 20 * time.Second
)

// ResolveScripts resolves every not-yet-resolved script definition
// in the import (config scripts and module-merged ones alike) and
// returns human-readable notes for the import report.
func (imp *Imported) ResolveScripts() []string {
	var notes []string
	for i := range imp.Engine.Scripts {
		sd := &imp.Engine.Scripts[i]
		if sd.Resolved != nil && sd.Resolved.Code != "" {
			continue
		}
		resolveOne(sd)
		if sd.Resolved.LoadError != "" {
			notes = append(notes, fmt.Sprintf("脚本「%s」加载失败：%s", sd.Name, sd.Resolved.LoadError))
		}
	}
	return notes
}

func resolveOne(sd *ScriptDef) {
	p := sd.Params
	presetSource := ""
	if sd.Resolved != nil {
		presetSource = sd.Resolved.Source // e.g. module attribution
	}
	r := &ResolvedScript{
		Type:         strings.ToLower(strings.TrimSpace(p["type"])),
		Pattern:      strings.TrimSpace(p["pattern"]),
		Source:       presetSource,
		RequiresBody: truthy(p["requires-body"]),
		Enabled:      true,
	}
	if v, ok := p["timeout"]; ok {
		r.TimeoutSec = atoi(v, 0)
	}
	for _, k := range []string{"enabled", "enable"} {
		if v, ok := p[k]; ok {
			r.Enabled = truthy(v)
		}
	}
	sd.Resolved = r

	path := strings.TrimSpace(p["script-path"])
	if path == "" {
		if r.Source == "" {
			r.Source = "Surge 配置"
		}
		r.LoadError = "缺少 script-path，未能取得脚本源码"
		return
	}
	if r.Source == "" {
		r.Source = path
	}

	var code []byte
	var err error
	if isHTTPURL(path) {
		code, err = downloadScript(path)
		if err != nil {
			r.LoadError = "远程脚本下载失败：" + err.Error()
			return
		}
	} else {
		code, err = os.ReadFile(path)
		if err != nil {
			r.LoadError = "本地脚本文件读取失败（面板导入只收到配置文件本身，本地相对路径通常不可达；请改用远程 URL 的 script-path）：" + err.Error()
			return
		}
	}
	if len(code) == 0 {
		r.LoadError = "脚本内容为空"
		return
	}
	r.Code = string(code)
	sum := sha256.Sum256(code)
	r.SHA256 = hex.EncodeToString(sum[:])
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func downloadScript(rawURL string) ([]byte, error) {
	client := &http.Client{Timeout: scriptDLTimeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SakuNet script-import")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxScriptBytes {
		return nil, fmt.Errorf("脚本超过 %d 字节上限", maxScriptBytes)
	}
	return body, nil
}
