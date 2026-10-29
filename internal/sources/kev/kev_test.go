package kev_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	sqldatabase "github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, catalog kev.Catalog) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(catalog))
	}))
}

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return logrus.NewEntry(l)
}

func sampleCatalog() kev.Catalog {
	return kev.Catalog{
		Title:          "CISA KEV",
		CatalogVersion: "2024.01.01",
		Count:          2,
		Vulnerabilities: []kev.Entry{
			{
				CveID:                      "CVE-2021-44228",
				KnownRansomwareCampaignUse: "Known",
				ShortDescription:           "Apache Log4j2 contains a remote code execution vulnerability.",
				Notes:                      "https://logging.apache.org/log4j/2.x/security.html ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04 ; https://nvd.nist.gov/vuln/detail/CVE-2021-44228; https://logging.apache.org/log4j/2.x/security.html",
			},
			{CveID: "CVE-2023-1234", KnownRansomwareCampaignUse: "Unknown"},
		},
	}
}

func TestCisaClient_Fetch(t *testing.T) {
	srv := newTestServer(t, sampleCatalog())
	defer srv.Close()

	assertions, err := kev.NewCisaClient(srv.URL).Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []kev.Assertion{
		{
			CveID:            "CVE-2021-44228",
			KnownRansomware:  true,
			ShortDescription: "Apache Log4j2 contains a remote code execution vulnerability.",
			ReferenceURLs: []string{
				"https://logging.apache.org/log4j/2.x/security.html",
				"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			},
		},
		{CveID: "CVE-2023-1234"},
	}, assertions)
}

func TestEntry_KnownRansomware(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"known", "Known", true},
		{"unknown", "Unknown", false},
		{"empty", "", false},
		{"other", "N/A", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := kev.Entry{KnownRansomwareCampaignUse: tc.value}
			assert.Equal(t, tc.expected, e.KnownRansomware())
		})
	}
}

func TestCisaClient_Fetch_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := kev.NewCisaClient(srv.URL).Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestCisaClient_Fetch_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	_, err := kev.NewCisaClient(srv.URL).Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding response")
}

func TestFetcher_Sync_AppliesAllCatalogEntries(t *testing.T) {
	srv := newTestServer(t, sampleCatalog())
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	expectUpdate(q, sqldatabase.UpsertKevSourceEntriesParams{
		CveIds:             []string{"CVE-2021-44228", "CVE-2023-1234"},
		Sources:            []string{"cisa", "cisa"},
		KnownRansomwareUse: []bool{true, false},
		ShortDescriptions:  []string{"Apache Log4j2 contains a remote code execution vulnerability.", ""},
		ReferenceUrls:      []string{"https://logging.apache.org/log4j/2.x/security.html\nhttps://nvd.nist.gov/vuln/detail/CVE-2021-44228", ""},
	})

	f := kev.NewFetcherWithQuerier(q, testLogger(), kev.NewCisaClient(srv.URL))
	require.NoError(t, f.Sync(context.Background()))
}

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/kev_catalog.json")
	require.NoError(t, err)
	return b
}

func newFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	raw := loadFixture(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
}

func TestCisaClient_Fetch_RealFixture(t *testing.T) {
	srv := newFixtureServer(t)
	defer srv.Close()

	var catalog kev.Catalog
	require.NoError(t, json.Unmarshal(loadFixture(t), &catalog))

	assertions, err := kev.NewCisaClient(srv.URL).Fetch(context.Background())
	require.NoError(t, err)

	assert.Greater(t, catalog.Count, 0)
	assert.Len(t, assertions, catalog.Count)

	known := 0
	for i, a := range assertions {
		assert.NotEmpty(t, a.CveID, "entry %d has empty CveID", i)
		assert.NotEmpty(t, a.ShortDescription, "entry %d has empty ShortDescription", i)
		assert.NotEmpty(t, a.ReferenceURLs, "entry %d has no reference URLs", i)
		if a.KnownRansomware {
			known++
		}
	}
	assert.Greater(t, known, 0)

	papercut := assertions[slices.IndexFunc(assertions, func(a kev.Assertion) bool { return a.CveID == "CVE-2023-27351" })]
	assert.Equal(t, []string{
		"https://www.papercut.com/kb/Main/PO-1216-and-PO-1219",
		"https://nvd.nist.gov/vuln/detail/CVE-2023-27351",
	}, papercut.ReferenceURLs)
}
