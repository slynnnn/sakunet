// Package api is a tiny client for sing-box's Clash-API-compatible
// endpoint (experimental.clash_api, 127.0.0.1:9090).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func New(base string) *Client {
	return &Client{Base: base, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

type Proxy struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Now     string   `json:"now"`
	All     []string `json:"all"`
	History []struct {
		Delay int `json:"delay"`
	} `json:"history,omitempty"`
}

type proxiesResponse struct {
	Proxies map[string]*Proxy `json:"proxies"`
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var buf *bytes.Buffer
	if body != nil {
		raw, _ := json.Marshal(body)
		buf = bytes.NewBuffer(raw)
	} else {
		buf = &bytes.Buffer{}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, buf)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, out.String())
	}
	return out.Bytes(), nil
}

// Version returns the sing-box version info from /version.
func (c *Client) Version(ctx context.Context) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	return v, json.Unmarshal(raw, &v)
}

// Proxies returns all proxy entries keyed by name.
func (c *Client) Proxies(ctx context.Context) (map[string]*Proxy, error) {
	raw, err := c.do(ctx, http.MethodGet, "/proxies", nil)
	if err != nil {
		return nil, err
	}
	var r proxiesResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return r.Proxies, nil
}

// Switch sets the current member of a selector group.
func (c *Client) Switch(ctx context.Context, group, name string) error {
	_, err := c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group),
		map[string]string{"name": name})
	return err
}

// Delay tests one outbound's latency through the core.
func (c *Client) Delay(ctx context.Context, name, testURL string, timeoutMS int) (int, error) {
	q := url.Values{}
	q.Set("url", testURL)
	q.Set("timeout", fmt.Sprint(timeoutMS))
	raw, err := c.do(ctx, http.MethodGet,
		"/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	var r struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0, err
	}
	return r.Delay, nil
}

// Connections returns cumulative traffic totals from /connections.
func (c *Client) Connections(ctx context.Context) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	return v, json.Unmarshal(raw, &v)
}

// Connection is one live connection as reported by /connections.
// Only fields sing-box actually provides are mapped; nothing is
// synthesised.
type Connection struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	DestPort    string   `json:"destination_port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Rule        string   `json:"rule,omitempty"`
	RulePayload string   `json:"rule_payload,omitempty"`
	Chains      []string `json:"chains"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Start       string   `json:"start,omitempty"`
}

// Activity is the parsed /connections payload for the activity tab.
type Activity struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
}

// Activity fetches and parses /connections including the live
// connection list.
func (c *Client) Activity(ctx context.Context) (*Activity, error) {
	raw, err := c.do(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	var wire struct {
		DownloadTotal int64 `json:"downloadTotal"`
		UploadTotal   int64 `json:"uploadTotal"`
		Connections   []struct {
			ID       string `json:"id"`
			Metadata struct {
				Host            string `json:"host"`
				DestinationPort string `json:"destinationPort"`
				Network         string `json:"network"`
			} `json:"metadata"`
			Upload      int64    `json:"upload"`
			Download    int64    `json:"download"`
			Start       string   `json:"start"`
			Chains      []string `json:"chains"`
			Rule        string   `json:"rule"`
			RulePayload string   `json:"rulePayload"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}
	act := &Activity{DownloadTotal: wire.DownloadTotal, UploadTotal: wire.UploadTotal, Connections: []Connection{}}
	for _, cn := range wire.Connections {
		act.Connections = append(act.Connections, Connection{
			ID: cn.ID, Host: cn.Metadata.Host, DestPort: cn.Metadata.DestinationPort,
			Network: cn.Metadata.Network, Rule: cn.Rule, RulePayload: cn.RulePayload,
			Chains: cn.Chains, Upload: cn.Upload, Download: cn.Download, Start: cn.Start,
		})
	}
	return act, nil
}
