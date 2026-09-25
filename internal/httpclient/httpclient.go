package httpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

func New(timeout time.Duration) Doer {
	return &http.Client{Timeout: timeout}
}

type StatusError struct {
	URL        string
	StatusCode int
}

func (e StatusError) Error() string {
	return fmt.Sprintf("GET %s returned HTTP %d", e.URL, e.StatusCode)
}

func Get(ctx context.Context, doer Doer, rawURL string, header http.Header) ([]byte, error) {
	resp, err := do(ctx, doer, rawURL, header)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", redact(rawURL), err)
	}
	return body, nil
}

func GetJSON(ctx context.Context, doer Doer, rawURL string, header http.Header, v any) error {
	resp, err := do(ctx, doer, rawURL, header)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decoding response from %s: %w", redact(rawURL), err)
	}
	return nil
}

func do(ctx context.Context, doer Doer, rawURL string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", redact(rawURL), redactURLError(err))
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", redact(rawURL), redactURLError(err))
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, StatusError{URL: redact(rawURL), StatusCode: resp.StatusCode}
	}
	return resp, nil
}

func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		safe := *urlErr
		safe.URL = redact(urlErr.URL)
		return &safe
	}
	return err
}

// redact drops the query, which may hold signatures for presigned URLs.
func redact(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid url>"
	}
	u.RawQuery = ""
	return u.String()
}
