package mitm

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"sakunet/internal/surge"
)

// Raw TCP tunnel isolation: CONNECT to a plain echo server through
// the proxy and confirm bytes flow both ways without TLS involved.
func TestTunnelRawTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(c)
		}
	}()
	target := ln.Addr().String()

	srv, err := Start(Config{
		Hostnames: []string{"mitm.only"},
		Engine:    (&surge.EngineData{}).Compile(),
		CA:        tls.Certificate{},
	}, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	c, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status: %s", status)
	}
	_, _ = br.ReadString('\n') // blank line
	if _, err := c.Write([]byte("hello-tunnel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("hello-tunnel"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "hello-tunnel" {
		t.Fatalf("echo = %q", buf)
	}
}
