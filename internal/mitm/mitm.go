package mitm

import (
	"bufio"
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

	"sakunet/internal/surge"
)

// Config configures the MITM proxy server.
type Config struct {
	Hostnames []string // imported [MITM] hostname list (supports *.suffix and -exclusions)
	Engine    *surge.CompiledEngine
	CA        tls.Certificate
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
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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
