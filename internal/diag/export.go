package diag

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"sakunet/internal/api"
	"sakunet/internal/core"
)

// REDACTION LIST — what the diagnostics bundle scrubs, in order:
//
//  1. Value-based: every credential value collected from the
//     active stores (core.Manager.Secrets): node server addresses,
//     passwords, PSKs, UUIDs, usernames, obfs passwords, Reality
//     keys, and every [MITM] parameter value (ca-p12 blob and CA
//     passphrase included). Occurrences anywhere in any bundled
//     text are replaced with "***".
//  2. Key-pattern-based: any `password|passwd|psk|secret|token|
//     ca-passphrase = value` / `: value` pair in free text (e.g.
//     core logs) has its value masked.
//  3. Blob-pattern-based: base64-alphabet runs of 180+ characters
//     (the shape of a ca-p12 blob, padding included) are masked
//     even if rule 1 missed them. The threshold stays well above
//     hashes and fingerprints (<= 128 hex chars), which remain
//     visible on purpose — support needs them.
//  4. Structural: raw nodes.json / imported.json are NEVER placed
//     in the bundle; only the credential-free structural summary
//     (core.ConfigSummary) and the migration report (credential-
//     free by design since v0.3, still passed through the
//     redactor) are included.
//
// Redact implements rules 1–3 and is unit-tested with fake
// credentials: none of the originals may appear in the output.
var keyValueSecretRe = regexp.MustCompile(`(?i)(password|passwd|psk|secret|token|ca-passphrase|ca_passphrase)["']?\s*[:=]\s*["']?[^\s"',}]+`)
var longBlobRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{180,}`)

// Redact scrubs secrets (rule 1) and secret-shaped patterns
// (rules 2–3) from text.
func Redact(text string, secrets []string) string {
	out := text
	// Longest first so a short secret cannot partially survive
	// inside a longer one.
	sorted := append([]string{}, secrets...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[j]) > len(sorted[i]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, s := range sorted {
		if s != "" {
			out = strings.ReplaceAll(out, s, "***")
		}
	}
	out = keyValueSecretRe.ReplaceAllStringFunc(out, func(m string) string {
		for i, c := range m {
			if c == ':' || c == '=' {
				return m[:i+1] + " ***"
			}
		}
		return "***"
	})
	out = longBlobRe.ReplaceAllString(out, "***")
	return out
}

// BuildBundle runs a fresh self-check and packs the redacted
// diagnostics zip. It returns the zip bytes and the check results.
func BuildBundle(mgr *core.Manager, clash *api.Client, version string) ([]byte, []Check, error) {
	checks := RunChecks(mgr, clash)
	secrets := mgr.Secrets()
	st := mgr.Status()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(Redact(content, secrets)))
		return err
	}
	marshal := func(v any) string {
		raw, _ := json.MarshalIndent(v, "", "  ")
		return string(raw)
	}

	ver := fmt.Sprintf("SakuNet %s\nOS/Arch: %s/%s\nCore: %s\nGenerated: %s\nSource: %s %s\n",
		version, runtime.GOOS, runtime.GOARCH, st.Version,
		time.Now().Format("2006-01-02 15:04:05"), st.SourceKind, st.SourceName)
	if err := add("version.txt", ver); err != nil {
		return nil, checks, err
	}
	if err := add("status.json", marshal(st)); err != nil {
		return nil, checks, err
	}
	if err := add("config-summary.json", marshal(mgr.ConfigSummary())); err != nil {
		return nil, checks, err
	}
	if err := add("selfcheck.json", marshal(checks)); err != nil {
		return nil, checks, err
	}
	if rep := mgr.ImportReport(); rep != nil {
		if err := add("import-report.json", marshal(rep)); err != nil {
			return nil, checks, err
		}
	}
	if tail := mgr.CoreLogTail(200); tail != "" {
		if err := add("core-log-tail.txt", tail); err != nil {
			return nil, checks, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, checks, err
	}
	return buf.Bytes(), checks, nil
}
