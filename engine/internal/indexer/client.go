// Package indexer is a minimal client for the Wazuh indexer (OpenSearch) REST
// API: the few calls the engine needs, with no external dependency.
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
	"time"
)

// Client talks to one indexer with basic auth.
type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
}

// New returns a Client. caFile, when set, is the only CA trusted for the
// indexer certificate.
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
	}, nil
}

// Error is a non-2xx answer from the indexer.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("indexer: HTTP %d: %s", e.Status, e.Body)
}

// Do sends body as JSON and decodes the answer into out when out is not nil.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {

	var reader io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("indexer: marshal: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)

	if err != nil {
		return err
	}

	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)

	if err != nil {
		return fmt.Errorf("indexer: %s %s: %w", method, path, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &Error{Status: resp.StatusCode, Body: string(msg)}
	}

	if out == nil {
		_, err := io.Copy(io.Discard, resp.Body)
		return err
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// Search runs a search on index (a name or pattern) and decodes the answer.
func (c *Client) Search(ctx context.Context, index string, query, out any) error {
	return c.Do(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_search", query, out)
}

// Put writes doc under id, replacing any earlier version.
func (c *Client) Put(ctx context.Context, index, id string, doc any) error {
	return c.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(id), doc, nil)
}

// EnsureIndex creates index with the given body (settings and mappings) when
// it does not exist yet. When it exists, the mappings are put again: new
// fields are added, existing ones must not change (the indexer refuses that).
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

	// Another engine may have created it in between.
	if e, ok := err.(*Error); ok && e.Status == http.StatusBadRequest && strings.Contains(e.Body, "resource_already_exists_exception") {
		return nil
	}

	return err
}
