package indexer

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
	"sync/atomic"
	"time"
)

type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
	requests atomic.Uint64
	slots    chan struct{}
}

const inFlight = 4

var retries = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}

func New(baseURL, user, password, caFile string) (*Client, error) {

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("indexer: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("indexer: no certificate in %s", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &Client{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		user:     user,
		password: password,
		http:     &http.Client{Transport: transport, Timeout: 60 * time.Second},
		slots:    make(chan struct{}, inFlight),
	}, nil
}

type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("indexer: HTTP %d: %s", e.Status, e.Body)
}

func (c *Client) Requests() uint64 { return c.requests.Load() }

func (c *Client) send(ctx context.Context, method, path, contentType string, body []byte) (*http.Response, error) {

	for attempt := 0; ; attempt++ {

		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		c.requests.Add(1)

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			<-c.slots
			return nil, err
		}
		req.SetBasicAuth(c.user, c.password)
		req.Header.Set("Content-Type", contentType)

		resp, err := c.http.Do(req)
		<-c.slots
		if err != nil {
			return nil, fmt.Errorf("indexer: %s %s: %w", method, path, err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return resp, nil
		}

		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		e := &Error{Status: resp.StatusCode, Body: string(msg)}

		busy := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !busy || attempt >= len(retries) {
			return nil, e
		}

		select {
		case <-time.After(retries[attempt]):
		case <-ctx.Done():
			return nil, e
		}
	}
}

func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {

	var raw []byte

	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return fmt.Errorf("indexer: marshal: %w", err)
		}
	}

	resp, err := c.send(ctx, method, path, "application/json", raw)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if out == nil {
		_, err := io.Copy(io.Discard, resp.Body)
		return err
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Bulk(ctx context.Context, body []byte) error {

	resp, err := c.send(ctx, http.MethodPost, "/_bulk", "application/x-ndjson", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			ID     string          `json:"_id"`
			Status int             `json:"status"`
			Error  json.RawMessage `json:"error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("indexer: bulk answer: %w", err)
	}

	if !out.Errors {
		return nil
	}

	failed, first := 0, ""
	for _, item := range out.Items {
		for _, r := range item {
			if r.Status > 299 {
				failed++
				if first == "" {
					first = fmt.Sprintf("%s: %s", r.ID, r.Error)
				}
			}
		}
	}
	return fmt.Errorf("indexer: bulk: %d of %d items failed, first %s", failed, len(out.Items), first)
}

func (c *Client) Search(ctx context.Context, index string, query, out any) error {
	return c.Do(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_search", query, out)
}

func (c *Client) Refresh(ctx context.Context, index string) error {
	return c.Do(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_refresh", nil, nil)
}

func (c *Client) Put(ctx context.Context, index, id string, doc any) error {
	return c.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(id), doc, nil)
}

func (c *Client) EnsureIndex(ctx context.Context, index string, body map[string]any) error {

	err := c.Do(ctx, http.MethodHead, "/"+url.PathEscape(index), nil, nil)

	if err == nil {
		mappings, ok := body["mappings"]
		if !ok {
			return nil
		}
		return c.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_mapping", mappings, nil)
	}

	if e, ok := err.(*Error); !ok || e.Status != http.StatusNotFound {
		return err
	}

	err = c.Do(ctx, http.MethodPut, "/"+url.PathEscape(index), body, nil)

	if e, ok := err.(*Error); ok && e.Status == http.StatusBadRequest && strings.Contains(e.Body, "resource_already_exists_exception") {
		return nil
	}

	return err
}
