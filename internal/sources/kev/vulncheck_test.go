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
	"slices"
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
			"cisa_date_added": "2026-01-02T00:00:00Z",
			"vulncheck_reported_exploitation": [
				{"url": "https://example.com/report"},
				{"url": ""},
				{"url": "https://example.com/report"},
				{"url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2026-0001&date=2026-10-14"},
				{"url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-01-03&vulnerability=cve-2026-0001", "date_added": "2026-01-03T00:00:00Z"},
				{"url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-01-05&vulnerability=cve-2026-0001", "date_added": "2026-01-05T00:00:00Z"},
				{"url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-01-04&vulnerability=cve-2026-0001", "date_added": "2026-01-04T00:00:00Z"},
				{"url": "https://example.com/advisory"}
			]
		},
		{
			"cve": ["CVE-2026-0003"],
			"shortDescription": "Copy of the NVD description.",
			"vulncheck_reported_exploitation": [
				{"url": "https://api.vulncheck.com/v3/index/vulncheck-canaries?cve=CVE-2026-0003&date=2026-10-14"}
			]
		}
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
			ReferenceURLs: []string{
				"https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-01-05&vulnerability=cve-2026-0001",
				"https://example.com/report", "https://example.com/advisory",
			},
		},
		{
			CveID: "CVE-2026-0002", KnownRansomware: true,
			ShortDescription: "Example vulnerability description.",
			ReferenceURLs: []string{
				"https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2026-01-05&vulnerability=cve-2026-0001",
				"https://example.com/report", "https://example.com/advisory",
			},
		},
		{CveID: "CVE-2026-0003"},
	}, assertions)
}

func TestVulnCheckReferenceURLsKeepsNewest(t *testing.T) {
	var entry vulnCheckEntry
	var expected []string
	for day := 1; day <= 12; day++ {
		url := fmt.Sprintf("https://example.com/report-%02d", day)
		entry.ReportedExploitation = append(entry.ReportedExploitation, vulnCheckExploitationReport{
			URL: url, DateAdded: fmt.Sprintf("2026-01-%02dT00:00:00Z", day),
		})
		if day > 2 {
			expected = append([]string{url}, expected...)
		}
	}
	assert.Equal(t, expected, entry.referenceURLs())
}

func TestVulnCheckReferenceURLsKeepsNewestDuplicate(t *testing.T) {
	const repeatedURL = "https://example.com/repeated"
	reports := []vulnCheckExploitationReport{
		{URL: repeatedURL, DateAdded: "2026-01-01T00:00:00Z"},
		{URL: repeatedURL, DateAdded: "2026-01-12T00:00:00Z"},
	}
	for day := 2; day <= 11; day++ {
		reports = append(reports, vulnCheckExploitationReport{
			URL:       fmt.Sprintf("https://example.com/report-%02d", day),
			DateAdded: fmt.Sprintf("2026-01-%02dT00:00:00Z", day),
		})
	}
	expected := []string{repeatedURL}
	for day := 11; day >= 3; day-- {
		expected = append(expected, fmt.Sprintf("https://example.com/report-%02d", day))
	}
	newestFirst := slices.Clone(reports)
	newestFirst[0], newestFirst[1] = newestFirst[1], newestFirst[0]

	for _, test := range []struct {
		name    string
		reports []vulnCheckExploitationReport
	}{
		{name: "oldest duplicate first", reports: reports},
		{name: "newest duplicate first", reports: newestFirst},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := vulnCheckEntry{ReportedExploitation: test.reports}
			assert.Equal(t, expected, entry.referenceURLs())
		})
	}
}
