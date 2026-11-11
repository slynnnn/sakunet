package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"sakunet/internal/script"
	"sakunet/internal/surge"
)

// Config configures the MITM proxy server.
type Config struct {
	Hostnames []string // imported [MITM] hostname list (supports *.suffix and -exclusions)
	Engine    *surge.CompiledEngine
	// Scripts, when non-nil, runs http-request / http-response JS
	// scripts (v1.1) inside the intercepted/plain pipelines.
	Scripts *script.Runner
	CA      tls.Certificate
	// UpstreamProxy is the sing-box mixed inbound ("127.0.0.1:2080").
	// Empty means dial origins directly (used by tests).
	UpstreamProxy string
	// UpstreamRoots verifies origin certificates; nil = system pool.
	UpstreamRoots    *x509.CertPool
	UpstreamInsecure bool
	Log              *log.Logger
}

type Server struct {
	cfg   Config
	ln    net.Listener
	http  *http.Server
	mu    sync.Mutex
	leafs map[string]*tls.Certificate
	done  chan struct{}
}

func (c *Config) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log.Printf("[mitm] "+format, args...)
	}
}

// MatchHostname reports whether host (with or without port) is in
// the MITM set. Entries: exact, "*.suffix", "*" (all); entries
// prefixed with "-" exclude.
func MatchHostname(list []string, host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	h = strings.ToLower(h)
	matched := false
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		excl := strings.HasPrefix(e, "-")
		e = strings.TrimPrefix(e, "-")
		if hp, _, err := net.SplitHostPort(e); err == nil {
			e = hp
		}
		hit := false
		switch {
		case e == "*":
			hit = true
		case strings.HasPrefix(e, "*."):
			hit = strings.HasSuffix(h, e[1:]) && h != e[2:]
		default:
			hit = h == e
		}
		if hit {
			if excl {
				return false
			}
			matched = true
		}
	}
	return matched
}

// Start binds the listener (127.0.0.1 only) and serves.
func Start(cfg Config, addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, ln: ln, leafs: map[string]*tls.Certificate{}, done: make(chan struct{})}
	s.http = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 15 * time.Second}
	go func() {
		_ = s.http.Serve(ln)
		close(s.done)
	}()
	return s, nil
}

// Addr returns the bound address ("127.0.0.1:port").
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the proxy.
func (s *Server) Close() {
	_ = s.http.Close()
	<-s.done
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// Plain HTTP with an absolute URI: rewrites apply without any
	// decryption. Surge evaluates rewrite rules against the full URL.
	if r.URL != nil && r.URL.IsAbs() {
		s.handlePlainHTTP(w, r)
		return
	}
	http.Error(w, "SakuNet MITM proxy: only proxy requests accepted", http.StatusBadRequest)
}

// --- CONNECT, non-MITM: blind tunnel through the upstream ---------

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host // host:port as sent by the client
	host := target
	if hp, _, err := net.SplitHostPort(target); err == nil {
		host = hp
	}
	if MatchHostname(s.cfg.Hostnames, host) {
		s.intercept(w, r, target, host)
		return
	}
	up, err := s.dialUpstream(target)
	if err != nil {
		s.cfg.logf("tunnel %s: %v", target, err)
		http.Error(w, "upstream connect failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()
	// Any bytes the client already pipelined (e.g. a TLS
	// ClientHello) sit in brw's read buffer; splice through a
	// wrapper that drains it first, or the tunnel starves.
	splice(&bufferedConn{Reader: brw, Conn: client}, up)
}

// dialUpstream returns a connection to target, chained through the
// sing-box mixed inbound when configured (CONNECT), else direct.
func (s *Server) dialUpstream(target string) (net.Conn, error) {
	if s.cfg.UpstreamProxy == "" {
		return net.DialTimeout("tcp", target, 15*time.Second)
	}
	c, err := net.DialTimeout("tcp", s.cfg.UpstreamProxy, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("upstream CONNECT %s: %s", target, resp.Status)
	}
	if br.Buffered() > 0 { // never expected right after CONNECT, but stay correct
		return &bufferedConn{Reader: br, Conn: c}, nil
	}
	return c, nil
}

type bufferedConn struct {
	io.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.Reader.Read(p) }

// CloseWrite/CloseRead delegate so splice can half-close the raw
// connection through the wrapper.
func (b *bufferedConn) CloseWrite() error {
	if tw, ok := b.Conn.(*net.TCPConn); ok {
		return tw.CloseWrite()
	}
	return nil
}

func (b *bufferedConn) CloseRead() error {
	if tw, ok := b.Conn.(*net.TCPConn); ok {
		return tw.CloseRead()
	}
	return nil
}

type writeCloser interface{ CloseWrite() error }

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if wc, ok := dst.(writeCloser); ok {
			_ = wc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// --- CONNECT, MITM host: terminate TLS, run the engine ------------

func (s *Server) intercept(w http.ResponseWriter, r *http.Request, target, host string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = brw.Flush()
	leaf, err := s.leafFor(host)
	if err != nil {
		s.cfg.logf("leaf %s: %v", host, err)
		client.Close()
		return
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	}
	// Same buffered-bytes concern as the tunnel path: the client's
	// ClientHello may already sit in brw's read buffer.
	tconn := tls.Server(&bufferedConn{Reader: brw, Conn: client}, tlsCfg)
	if err := tconn.Handshake(); err != nil {
		s.cfg.logf("handshake %s: %v", host, err)
		tconn.Close()
		return
	}
	defer tconn.Close()
	br := bufio.NewReader(tconn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed or protocol error: end of connection
		}
		closeAfter := req.Close
		cont := s.serveIntercepted(tconn, req, host)
		_ = req.Body.Close()
		if !cont || closeAfter {
			return
		}
	}
}

func (s *Server) leafFor(host string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.leafs[host]; ok {
		return c, nil
	}
	caCert := s.cfg.CA.Leaf
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, s.cfg.CA.PrivateKey)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leafCert}
	s.leafs[host] = c
	return c, nil
}

// serveIntercepted runs one decrypted request through the rewrite
// engine and the upstream. Returns false when the connection must
// be closed (redirect/reject answers, transport errors).
func (s *Server) serveIntercepted(client net.Conn, req *http.Request, host string) bool {
	fullURL := "https://" + host + req.URL.RequestURI()

	// Request-side rules, in order; first decisive rule wins.
	for _, rule := range s.cfg.Engine.Rules {
		if !rule.Match(fullURL) {
			continue
		}
		switch rule.Op {
		case surge.OpRedirect:
			loc := rule.ApplyRedirect(fullURL)
			_ = writeSimple(client, rule.Status, "Moved", map[string]string{"Location": loc})
			return false // writeSimple answers with Connection: close
		case surge.OpReject:
			_ = writeReject(client, rule)
			return false
		case surge.OpHeader:
			if rule.Direction == "request" {
				applyHeaderOp(req.Header, rule)
			}
		}
	}

	// Native request-body rewrites (v1.2): after the other request
	// rules, before scripts (scripts see the rewritten body).
	s.applyRequestBody(req, fullURL)

	// Request scripts (v1.1): after rewrite header ops, before
	// forwarding. A script may rewrite URL/headers/body or answer
	// the request itself (reject/mock short-circuit).
	if respond, newURL := s.scriptRequest(req, fullURL); respond != nil {
		_ = writeScriptResponse(client, respond)
		return false
	} else if newURL != "" && newURL != fullURL {
		if u, err := url.Parse(newURL); err == nil && u.Host != "" {
			req.Host = u.Host
			req.URL.Path = u.Path
			req.URL.RawQuery = u.RawQuery
			fullURL = newURL
			host = u.Hostname()
		}
	}

	// Forward to the origin through the upstream.
	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	up, err := s.dialTLSUpstream(target, host)
	if err != nil {
		s.cfg.logf("upstream %s: %v", req.Host, err)
		_ = writeSimple(client, http.StatusBadGateway, "Bad Gateway", nil)
		return false
	}
	defer up.Close()
	// Normalise the request for the origin.
	req.RequestURI = ""
	req.URL.Scheme = "https"
	req.URL.Host = req.Host
	req.Close = false
	if err := req.Write(up); err != nil {
		return false
	}
	br := bufio.NewReader(up)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Response-side rules.
	respURL := fullURL
	for _, rule := range s.cfg.Engine.Rules {
		if rule.Op == surge.OpHeader && rule.Direction == "response" && rule.Match(respURL) {
			applyHeaderOp(resp.Header, rule)
		}
	}
	// Native response-body rewrites (v1.2), before scripts.
	s.rewriteResponseBody(resp, respURL)
	// Response scripts (v1.1) run last, over the final headers.
	s.scriptResponse(resp, respURL, req)
	// Response.Write would strip/keep framing itself; keep the
	// connection usable for the next request when possible.
	keepAlive := !resp.Close
	if err := resp.Write(client); err != nil {
		return false
	}
	return keepAlive
}

// dialTLSUpstream dials the origin (through the sing-box chain when
// configured) and completes the client TLS handshake.
func (s *Server) dialTLSUpstream(target, serverName string) (net.Conn, error) {
	c, err := s.dialUpstream(target)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, &tls.Config{
		ServerName:         serverName,
		RootCAs:            s.cfg.UpstreamRoots,
		InsecureSkipVerify: s.cfg.UpstreamInsecure, //nolint: test-only knob, default false
		NextProtos:         []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

// --- Plain HTTP ----------------------------------------------------

func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	fullURL := r.URL.String()
	for _, rule := range s.cfg.Engine.Rules {
		if !rule.Match(fullURL) {
			continue
		}
		switch rule.Op {
		case surge.OpRedirect:
			w.Header().Set("Location", rule.ApplyRedirect(fullURL))
			w.WriteHeader(rule.Status)
			return
		case surge.OpReject:
			writeRejectHTTP(w, rule)
			return
		case surge.OpHeader:
			if rule.Direction == "request" {
				applyHeaderOp(r.Header, rule)
			}
		}
	}
	// Native request-body rewrites (v1.2).
	s.applyRequestBody(r, fullURL)
	// Forward via the upstream proxy (or directly in tests).
	var proxyFn func(*http.Request) (*url.URL, error)
	if s.cfg.UpstreamProxy != "" {
		proxyFn = http.ProxyURL(&url.URL{Scheme: "http", Host: s.cfg.UpstreamProxy})
	}
	tr := &http.Transport{
		Proxy:               proxyFn,
		TLSClientConfig:     &tls.Config{RootCAs: s.cfg.UpstreamRoots, InsecureSkipVerify: s.cfg.UpstreamInsecure}, //nolint
		TLSHandshakeTimeout: 15 * time.Second,
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	// Request scripts (v1.1).
	if respond, newURL := s.scriptRequest(outReq, fullURL); respond != nil {
		for k, vs := range respond.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(respond.Status)
		_, _ = w.Write(respond.Body)
		return
	} else if newURL != "" && newURL != fullURL {
		if u, err := url.Parse(newURL); err == nil {
			outReq.URL = u
			outReq.Host = u.Host
			fullURL = newURL
		}
	}
	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, rule := range s.cfg.Engine.Rules {
		if rule.Op == surge.OpHeader && rule.Direction == "response" && rule.Match(fullURL) {
			applyHeaderOp(resp.Header, rule)
		}
	}
	// Native response-body rewrites (v1.2), before scripts.
	s.rewriteResponseBody(resp, fullURL)
	// Response scripts (v1.1) run last, over the final headers.
	s.scriptResponse(resp, fullURL, outReq)
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue // re-emitted below from the (possibly scripted) body
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", fmt.Sprint(resp.ContentLength))
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// --- Native body rewrites (v1.2) ----------------------------------

// bodyRulesFor returns the compiled body rules of one direction
// matching url, in configuration order.
func (s *Server) bodyRulesFor(direction, fullURL string) []*surge.CompiledRule {
	if s.cfg.Engine == nil {
		return nil
	}
	var out []*surge.CompiledRule
	for _, rule := range s.cfg.Engine.Rules {
		if rule.Op == surge.OpBody && rule.Direction == direction && rule.Match(fullURL) {
			out = append(out, rule)
		}
	}
	return out
}

// identityEncoded reports whether a payload is carried without a
// content encoding the body layer cannot safely rewrite (anything
// but absent/identity is left untouched — encoded payloads are
// the script engine's job, which decodes gzip itself).
func identityEncoded(h http.Header) bool {
	ce := strings.TrimSpace(strings.ToLower(h.Get("Content-Encoding")))
	return ce == "" || ce == "identity"
}

func applyBodyRules(body []byte, rules []*surge.CompiledRule) []byte {
	for _, r := range rules {
		body = r.ApplyBody(body)
	}
	return body
}

// applyRequestBody buffers the request body (up to the shared
// cap) and applies matching native request-body rules in place.
func (s *Server) applyRequestBody(req *http.Request, fullURL string) {
	rules := s.bodyRulesFor("request", fullURL)
	if len(rules) == 0 || req.Body == nil || req.ContentLength == 0 {
		return
	}
	if !identityEncoded(req.Header) {
		s.cfg.logf("body-rewrite: request %s skipped (Content-Encoding %q)", fullURL, req.Header.Get("Content-Encoding"))
		return
	}
	buf, err := io.ReadAll(io.LimitReader(req.Body, maxScriptBody+1))
	if err != nil {
		return
	}
	if len(buf) > maxScriptBody {
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
		s.cfg.logf("body-rewrite: request %s exceeds %d bytes, passed through unmodified", fullURL, maxScriptBody)
		return
	}
	_ = req.Body.Close()
	out := applyBodyRules(buf, rules)
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	req.Header.Set("Content-Length", fmt.Sprint(len(out)))
}

// rewriteResponseBody buffers the response body (up to the shared
// cap) and applies matching native response-body rules in place,
// fixing the framing headers afterwards.
func (s *Server) rewriteResponseBody(resp *http.Response, fullURL string) {
	rules := s.bodyRulesFor("response", fullURL)
	if len(rules) == 0 || resp.Body == nil {
		return
	}
	if !identityEncoded(resp.Header) {
		s.cfg.logf("body-rewrite: response %s skipped (Content-Encoding %q)", fullURL, resp.Header.Get("Content-Encoding"))
		return
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBody+1))
	if err != nil {
		return
	}
	if len(buf) > maxScriptBody {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), resp.Body))
		s.cfg.logf("body-rewrite: response %s exceeds %d bytes, passed through unmodified", fullURL, maxScriptBody)
		return
	}
	_ = resp.Body.Close()
	out := applyBodyRules(buf, rules)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
}

// --- JS script pipeline (v1.1) -------------------------------------

// maxScriptBody caps how much request/response body the script
// layer buffers. Larger payloads stream through unscripted.
const maxScriptBody = 4 << 20

// scriptRequest runs matching http-request scripts against req,
// mutating it in place (headers, body). It returns a non-nil
// *script.Response when a script short-circuits the request
// (reject/mock), plus the possibly rewritten full URL.
func (s *Server) scriptRequest(req *http.Request, fullURL string) (*script.Response, string) {
	sr := s.cfg.Scripts
	if sr == nil || !sr.Runnable(script.TypeRequest, fullURL) {
		return nil, fullURL
	}
	sreq := &script.Request{Method: req.Method, URL: fullURL, Headers: req.Header}
	bodyBuffered := false
	if sr.NeedsBody(fullURL) && req.Body != nil {
		prefix, err := io.ReadAll(io.LimitReader(req.Body, maxScriptBody+1))
		if err == nil {
			if len(prefix) > maxScriptBody {
				// Too large to script: restore the stream untouched.
				req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), req.Body))
				s.cfg.logf("script: request body exceeds %d bytes, body not exposed for %s", maxScriptBody, fullURL)
			} else {
				sreq.Body = prefix
				bodyBuffered = true
			}
		}
	}
	out := sr.RunRequest(sreq)
	if out.Respond != nil {
		return out.Respond, fullURL
	}
	if out.Headers != nil {
		req.Header = out.Headers
	}
	if bodyBuffered {
		body := sreq.Body
		if out.BodySet {
			body = out.Body
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Del("Content-Length") // framing derives from ContentLength on Write
	}
	return nil, out.URL
}

// scriptResponse runs matching http-response scripts over resp,
// mutating status/headers/body in place. Bodies above the cap (or
// with an undecodable Content-Encoding that a script changed) are
// handled conservatively: unmodified traffic is restored
// byte-for-byte.
func (s *Server) scriptResponse(resp *http.Response, fullURL string, origReq *http.Request) {
	sr := s.cfg.Scripts
	if sr == nil || !sr.Runnable(script.TypeResponse, fullURL) {
		return
	}
	if resp.Body == nil {
		return
	}
	prefix, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBody+1))
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(prefix))
		return
	}
	if len(prefix) > maxScriptBody {
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), resp.Body))
		s.cfg.logf("script: response body exceeds %d bytes, scripts skipped for %s", maxScriptBody, fullURL)
		return
	}
	_ = resp.Body.Close()
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	scriptBody, decoded := decodeForScript(prefix, enc)
	sreq := &script.Request{Method: origReq.Method, URL: fullURL, Headers: origReq.Header}
	out := sr.RunResponse(fullURL, sreq, &script.Response{
		Status: resp.StatusCode, Headers: resp.Header, Body: scriptBody,
	})
	resp.StatusCode = out.Status
	resp.Status = fmt.Sprintf("%d %s", out.Status, http.StatusText(out.Status))
	resp.Header = out.Headers
	if bytes.Equal(out.Body, scriptBody) {
		// Unmodified: restore the original wire bytes (still
		// encoded if they arrived encoded).
		resp.Body = io.NopCloser(bytes.NewReader(prefix))
		return
	}
	// Modified: the script's body is authoritative and unencoded.
	resp.Body = io.NopCloser(bytes.NewReader(out.Body))
	resp.ContentLength = int64(len(out.Body))
	resp.Header.Del("Content-Length")
	if decoded {
		resp.Header.Del("Content-Encoding")
	}
}

// decodeForScript transparently decompresses gzip/deflate bodies
// so scripts see the text they expect (Surge behaves the same).
// Returns (bodyForScript, wasDecoded).
func decodeForScript(body []byte, enc string) ([]byte, bool) {
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, false
		}
		defer zr.Close()
		dec, err := io.ReadAll(io.LimitReader(zr, maxScriptBody+1))
		if err != nil || len(dec) > maxScriptBody {
			return body, false
		}
		return dec, true
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, false
		}
		defer zr.Close()
		dec, err := io.ReadAll(io.LimitReader(zr, maxScriptBody+1))
		if err != nil || len(dec) > maxScriptBody {
			return body, false
		}
		return dec, true
	}
	return body, false
}

// writeScriptResponse answers an intercepted request directly
// from a script's {response:{...}} $done (reject/mock).
func writeScriptResponse(c net.Conn, rp *script.Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", rp.Status, http.StatusText(rp.Status))
	for k, vs := range rp.Headers {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(rp.Body))
	if _, err := io.WriteString(c, b.String()); err != nil {
		return err
	}
	_, err := c.Write(rp.Body)
	return err
}

// --- helpers --------------------------------------------------------

func applyHeaderOp(h http.Header, rule *surge.CompiledRule) {
	switch rule.HeaderOp {
	case "set":
		h.Set(rule.Name, rule.Value)
	case "add":
		h.Add(rule.Name, rule.Value)
	case "del":
		h.Del(rule.Name)
	}
}

var gif1x1 = func() []byte {
	b, _ := base64.StdEncoding.DecodeString("R0lGODlhAQABAAAAACw=")
	return b
}()

func writeSimple(c net.Conn, status int, text string, headers map[string]string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n", status, text)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(c, b.String())
	return err
}

func writeReject(c net.Conn, rule *surge.CompiledRule) error {
	body, ctype := rejectBody(rule.RejectTpl)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		rule.Status, http.StatusText(rule.Status), ctype, len(body))
	_, err := io.WriteString(c, b.String())
	if err != nil {
		return err
	}
	_, err = c.Write(body)
	return err
}

func writeRejectHTTP(w http.ResponseWriter, rule *surge.CompiledRule) {
	body, ctype := rejectBody(rule.RejectTpl)
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(rule.Status)
	_, _ = w.Write(body)
}

func rejectBody(tpl string) ([]byte, string) {
	switch tpl {
	case "img":
		return gif1x1, "image/gif"
	case "dict":
		return []byte("{}"), "application/json"
	case "array":
		return []byte("[]"), "application/json"
	default:
		return nil, "text/plain"
	}
}
