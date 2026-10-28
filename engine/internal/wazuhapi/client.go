package wazuhapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	mu    sync.Mutex
	token string
}

type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// New trusts caFile when given; serverName overrides the name checked in the API certificate, whose
// default one only names localhost.
func New(baseURL, user, password, caFile, serverName string) (*Client, error) {

	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("wazuh api: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("wazuh api: no certificate in %s", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig

	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		user:     user,
		password: password,
		http:     &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}, nil
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("wazuh api: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) authenticate(ctx context.Context) (string, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" {
		return c.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("wazuh api: authenticate: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Body: string(body)}
	}

	c.token = strings.TrimSpace(string(body))
	return c.token, nil
}

func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {

	for attempt := 0; ; attempt++ {

		token, err := c.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("wazuh api: %s %s: %w", method, path, err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Tokens expire after 15 minutes by default: one new token, then give up.
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.forget(token)
			continue
		}
		if resp.StatusCode >= 300 {
			return nil, &Error{Status: resp.StatusCode, Body: string(out)}
		}

		return out, nil
	}
}

const agentsPage = 500

func (c *Client) GroupAgents(ctx context.Context, group string) ([]Agent, error) {

	var agents []Agent

	for offset := 0; ; offset += agentsPage {

		path := fmt.Sprintf("/groups/%s/agents?select=id,name&limit=%d&offset=%d", url.PathEscape(group), agentsPage, offset)
		body, err := c.do(ctx, http.MethodGet, path, "", nil)
		if err != nil {
			return nil, err
		}

		var page struct {
			Data struct {
				AffectedItems      []Agent `json:"affected_items"`
				TotalAffectedItems int     `json:"total_affected_items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("wazuh api: agents of %s: %w", group, err)
		}

		agents = append(agents, page.Data.AffectedItems...)
		if len(page.Data.AffectedItems) < agentsPage || len(agents) >= page.Data.TotalAffectedItems {
			return agents, nil
		}
	}
}

func (c *Client) GroupConfiguration(ctx context.Context, group string) (string, error) {

	body, err := c.do(ctx, http.MethodGet, "/groups/"+url.PathEscape(group)+"/files/agent.conf?raw=true", "", nil)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// PutGroupConfiguration makes the manager validate the file before storing it; a rejected file
// changes nothing.
func (c *Client) PutGroupConfiguration(ctx context.Context, group, conf string) error {

	_, err := c.do(ctx, http.MethodPut, "/groups/"+url.PathEscape(group)+"/configuration", "application/xml", []byte(conf))
	return err
}
