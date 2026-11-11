// Package mitm implements SakuNet's MITM / URL-rewrite engine: a
// local HTTP proxy that sits in front of the sing-box mixed inbound.
// Only HTTPS connections whose host matches the imported config's
// [MITM] hostname list are decrypted and rewritten; everything else
// is tunneled through untouched.
package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// LoadCA decodes the user's Surge CA from the [MITM] section values:
// ca-p12 (base64 PKCS#12) and ca-passphrase. Decoding happens in
// memory only; the private key never touches disk or logs here.
func LoadCA(params map[string]string) (tls.Certificate, *x509.Certificate, error) {
	b64 := params["ca-p12"]
	pass := params["ca-passphrase"]
	if b64 == "" {
		return tls.Certificate{}, nil, fmt.Errorf("配置 [MITM] 段没有 ca-p12（无 CA，引擎待机）")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("ca-p12 不是合法 base64：%w", err)
	}
	key, cert, _, err := pkcs12.DecodeChain(raw, pass)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("ca-p12 解码失败（口令不符或格式过新）：%w", err)
	}
	if cert == nil || key == nil {
		return tls.Certificate{}, nil, fmt.Errorf("ca-p12 里没有证书/私钥")
	}
	if !cert.IsCA {
		return tls.Certificate{}, nil, fmt.Errorf("ca-p12 中的证书不是 CA 证书")
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	return tlsCert, cert, nil
}
