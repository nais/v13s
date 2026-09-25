package httpclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/nais/v13s/internal/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type payload struct {
	Name string `json:"name"`
}

type failingDoer struct {
	err error
}

func (d failingDoer) Do(*http.Request) (*http.Response, error) {
	return nil, d.err
}

func TestGetJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"name":"kev"}`))
	}))
	defer srv.Close()

	var v payload
	header := http.Header{"Authorization": []string{"Bearer token"}}
	require.NoError(t, httpclient.GetJSON(context.Background(), httpclient.New(time.Second), srv.URL, header, &v))
	assert.Equal(t, "kev", v.Name)
}

func TestGet_StatusErrorRedactsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := httpclient.Get(context.Background(), httpclient.New(time.Second), srv.URL+"/file.zip?X-Signature=secret", nil)
	require.Error(t, err)

	var statusErr httpclient.StatusError
	require.True(t, errors.As(err, &statusErr))
	assert.Equal(t, http.StatusForbidden, statusErr.StatusCode)
	assert.NotContains(t, err.Error(), "secret")
	assert.Contains(t, err.Error(), "/file.zip")
}

func TestGet_RequestErrorRedactsQuery(t *testing.T) {
	rawURL := "https://serve.vulncheck.com/file.zip?X-Signature=secret"
	doer := failingDoer{err: &url.Error{Op: "Get", URL: rawURL, Err: context.DeadlineExceeded}}

	_, err := httpclient.Get(context.Background(), doer, rawURL, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret")
	assert.Contains(t, err.Error(), "/file.zip")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestGetJSON_InvalidBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	var v map[string]any
	err := httpclient.GetJSON(context.Background(), httpclient.New(time.Second), srv.URL, nil, &v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding response")
}
