// Package osclient is a minimal OpenSearch REST client on the Go standard
// library only, so the whole project stays a single dependency-free binary.
package osclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"zemen/internal/config"
)

// Client wraps http.Client for one OpenSearch / Wazuh-indexer endpoint.
type Client struct {
	baseURL, username, password, apiKey string
	http                                *http.Client
}

// New builds a Client from a loaded Config.
func New(cfg config.Config) *Client {
	tr := &http.Transport{}
	if cfg.InsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit opt-in
	}
	return &Client{
		baseURL: cfg.BaseURL, username: cfg.Username, password: cfg.Password, apiKey: cfg.APIKey,
		http: &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

// APIError is a non-2xx response, keeping the body for actionable messages.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	b := e.Body
	if len(b) > 600 {
		b = b[:600] + "..."
	}
	return fmt.Sprintf("opensearch %s %s -> HTTP %d: %s", e.Method, e.Path, e.StatusCode, b)
}

// IsNotFound reports whether err is an HTTP 404 APIError.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

func (c *Client) do(method, path string, body []byte, ctype string) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rd)
	if err != nil {
		return nil, 0, fmt.Errorf("building request: %w", err)
	}
	if body != nil {
		if ctype == "" {
			ctype = "application/json"
		}
		req.Header.Set("Content-Type", ctype)
	}
	switch {
	case c.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+c.apiKey)
	case c.username != "":
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("calling opensearch: %w", err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return rb, resp.StatusCode, &APIError{resp.StatusCode, method, path, string(rb)}
	}
	return rb, resp.StatusCode, nil
}

// Ping returns the cluster's root info (version etc).
func (c *Client) Ping() ([]byte, error) {
	b, _, err := c.do(http.MethodGet, "/", nil, "")
	return b, err
}

// IndexExists returns true if the index exists.
func (c *Client) IndexExists(index string) (bool, error) {
	_, st, err := c.do(http.MethodHead, "/"+index, nil, "")
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return st == http.StatusOK, nil
}

// CreateIndex creates an index from a raw settings+mappings body.
func (c *Client) CreateIndex(index string, body []byte) error {
	_, _, err := c.do(http.MethodPut, "/"+index, body, "")
	return err
}

// PutMapping adds properties to an existing index (additive only).
func (c *Client) PutMapping(index string, body []byte) error {
	_, _, err := c.do(http.MethodPut, "/"+index+"/_mapping", body, "")
	return err
}

// Refresh makes recent writes searchable.
func (c *Client) Refresh(index string) error {
	_, _, err := c.do(http.MethodPost, "/"+index+"/_refresh", nil, "")
	return err
}

// IndexDoc upserts one document by id.
func (c *Client) IndexDoc(index, id string, doc any) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshalling document: %w", err)
	}
	_, _, err = c.do(http.MethodPut, "/"+index+"/_doc/"+url.PathEscape(id), b, "")
	return err
}

// GetDoc fetches one document's _source; found=false on 404.
func (c *Client) GetDoc(index, id string) (src []byte, found bool, err error) {
	rb, _, err := c.do(http.MethodGet, "/"+index+"/_doc/"+url.PathEscape(id), nil, "")
	if err != nil {
		if IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var env struct {
		Found  bool            `json:"found"`
		Source json.RawMessage `json:"_source"`
	}
	if err := json.Unmarshal(rb, &env); err != nil {
		return nil, false, fmt.Errorf("decoding get response: %w", err)
	}
	return env.Source, env.Found, nil
}

// DeleteDoc removes one document (404 is not an error).
func (c *Client) DeleteDoc(index, id string) error {
	_, _, err := c.do(http.MethodDelete, "/"+index+"/_doc/"+url.PathEscape(id), nil, "")
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

// BulkItem is one action in a bulk request. Doc is nil for deletes.
type BulkItem struct {
	Action string // "index" or "delete"
	Index  string
	ID     string
	Doc    any
}

// Bulk sends items in batches; it returns a list of per-item failures.
func (c *Client) Bulk(items []BulkItem, refresh bool) ([]string, error) {
	var failures []string
	const batch = 500
	for start := 0; start < len(items); start += batch {
		end := start + batch
		if end > len(items) {
			end = len(items)
		}
		var buf bytes.Buffer
		for _, it := range items[start:end] {
			meta, _ := json.Marshal(map[string]any{it.Action: map[string]any{"_index": it.Index, "_id": it.ID}})
			buf.Write(meta)
			buf.WriteByte('\n')
			if it.Action != "delete" {
				d, err := json.Marshal(it.Doc)
				if err != nil {
					return failures, fmt.Errorf("marshalling bulk doc %s: %w", it.ID, err)
				}
				buf.Write(d)
				buf.WriteByte('\n')
			}
		}
		path := "/_bulk"
		if refresh {
			path += "?refresh=true"
		}
		rb, _, err := c.do(http.MethodPost, path, buf.Bytes(), "application/x-ndjson")
		if err != nil {
			return failures, err
		}
		var resp struct {
			Errors bool `json:"errors"`
			Items  []map[string]struct {
				ID     string          `json:"_id"`
				Status int             `json:"status"`
				Error  json.RawMessage `json:"error"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rb, &resp); err != nil {
			return failures, fmt.Errorf("decoding bulk response: %w", err)
		}
		if resp.Errors {
			for _, m := range resp.Items {
				for act, r := range m {
					if r.Status >= 300 && !(act == "delete" && r.Status == 404) {
						failures = append(failures, fmt.Sprintf("%s %s: %s", act, r.ID, string(r.Error)))
					}
				}
			}
		}
	}
	return failures, nil
}

// Search runs a raw query DSL search and returns the raw body.
func (c *Client) Search(index string, query any) ([]byte, error) {
	b, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshalling query: %w", err)
	}
	rb, _, err := c.do(http.MethodPost, "/"+index+"/_search", b, "")
	return rb, err
}

// Get issues a raw GET against an arbitrary path (plugin APIs).
func (c *Client) Get(path string) ([]byte, error) {
	rb, _, err := c.do(http.MethodGet, path, nil, "")
	return rb, err
}

// Post issues a raw POST with a JSON body against an arbitrary path.
func (c *Client) Post(path string, body any) ([]byte, error) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("marshalling body: %w", err)
		}
	}
	rb, _, err := c.do(http.MethodPost, path, b, "")
	return rb, err
}

// Hit is one typed search hit.
type Hit[T any] struct {
	ID     string
	Source T
}

// SearchAs runs a search and decodes hits into T. A missing index yields
// an empty result rather than an error.
func SearchAs[T any](c *Client, index string, query any) ([]Hit[T], error) {
	rb, err := c.Search(index, query)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var env struct {
		Hits struct {
			Hits []struct {
				ID     string `json:"_id"`
				Source T      `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(rb, &env); err != nil {
		return nil, fmt.Errorf("decoding search response from %s: %w", index, err)
	}
	out := make([]Hit[T], 0, len(env.Hits.Hits))
	for _, h := range env.Hits.Hits {
		out = append(out, Hit[T]{ID: h.ID, Source: h.Source})
	}
	return out, nil
}

// AllDocs returns up to 10000 documents of an index.
func AllDocs[T any](c *Client, index string) ([]Hit[T], error) {
	return SearchAs[T](c, index, map[string]any{"size": 10000, "query": map[string]any{"match_all": map[string]any{}}})
}

// Wildcard reports whether name matches an OpenSearch-style pattern that
// supports '*' (e.g. "postgres-logs*").
func Wildcard(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(name, parts[i])
		if j < 0 {
			return false
		}
		name = name[j+len(parts[i]):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(name, last) && len(name) >= len(last)
}
