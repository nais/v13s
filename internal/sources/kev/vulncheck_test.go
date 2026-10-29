package kev

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type vulnCheckTransport func(*http.Request) (*http.Response, error)

func (f vulnCheckTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestVulnCheckClientFetchGuidance(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("kev.json")
	require.NoError(t, err)
	_, err = io.WriteString(file, `[
		{
			"cve": ["CVE-2026-0001", "CVE-2026-0002"],
			"knownRansomwareCampaignUse": "Known",
			"shortDescription": "Example vulnerability description.",
			"vulncheck_reported_exploitation": [
				{"url": "https://example.com/report"},
				{"url": ""},
				{"url": "https://example.com/report"},
				{"url": "https://example.com/advisory"}
			]
		},
		{"cve": ["CVE-2026-0003"]}
	]`)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	sum := sha256.Sum256(archive.Bytes())
	client := NewVulnCheckClient("https://example.com", "")
	client.http = &http.Client{Transport: vulnCheckTransport(func(r *http.Request) (*http.Response, error) {
		var body io.Reader
		switch r.URL.Path {
		case "/v3/backup/vulncheck-kev":
			body = strings.NewReader(`{"data":[{"url":"https://example.com/kev.zip","sha256":"` + hex.EncodeToString(sum[:]) + `"}]}`)
		case "/kev.zip":
			body = bytes.NewReader(archive.Bytes())
		default:
			return nil, fmt.Errorf("unexpected request path %q", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body)}, nil
	})}

	assertions, err := client.Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []Assertion{
		{
			CveID: "CVE-2026-0001", KnownRansomware: true,
			ShortDescription: "Example vulnerability description.",
			ReferenceURLs:    []string{"https://example.com/report", "https://example.com/advisory"},
		},
		{
			CveID: "CVE-2026-0002", KnownRansomware: true,
			ShortDescription: "Example vulnerability description.",
			ReferenceURLs:    []string{"https://example.com/report", "https://example.com/advisory"},
		},
		{CveID: "CVE-2026-0003"},
	}, assertions)
}
