package kev_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	sqldatabase "github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
			{CveID: "CVE-2021-44228", KnownRansomwareCampaignUse: "Known"},
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
		{CveID: "CVE-2021-44228", KnownRansomware: true},
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
	bulkUpdate := q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             []string{"CVE-2021-44228", "CVE-2023-1234"},
		KnownRansomwareUse: []bool{true, false},
		SourceCveIds:       []string{"CVE-2021-44228", "CVE-2023-1234"},
		SourceNames:        []string{"cisa", "cisa"},
		FetchedSources:     []string{"cisa"},
		Complete:           true,
	}).Return(int64(2), nil)
	updatePriority := q.EXPECT().UpdateCvePriority(mock.Anything).Return(int64(0), nil)
	mock.InOrder(bulkUpdate.Call, updatePriority.Call)

	f := kev.NewFetcher(q, testLogger(), kev.NewCisaClient(srv.URL))
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
		if a.KnownRansomware {
			known++
		}
	}
	assert.Greater(t, known, 0)
}

func TestFetcher_Sync_RealFixture(t *testing.T) {
	srv := newFixtureServer(t)
	defer srv.Close()

	var catalog kev.Catalog
	require.NoError(t, json.Unmarshal(loadFixture(t), &catalog))

	vulns := slices.Clone(catalog.Vulnerabilities)
	slices.SortFunc(vulns, func(a, b kev.Entry) int { return strings.Compare(a.CveID, b.CveID) })
	var expected sqldatabase.BulkUpdateKevDataParams
	for _, v := range vulns {
		expected.CveIds = append(expected.CveIds, v.CveID)
		expected.KnownRansomwareUse = append(expected.KnownRansomwareUse, v.KnownRansomware())
		expected.SourceCveIds = append(expected.SourceCveIds, v.CveID)
		expected.SourceNames = append(expected.SourceNames, kev.SourceCISA)
	}
	expected.FetchedSources = []string{"cisa"}
	expected.Complete = true

	q := mockquerier.NewMockQuerier(t)
	bulkUpdate := q.EXPECT().BulkUpdateKevData(mock.Anything, expected).Return(int64(1587), nil)
	updatePriority := q.EXPECT().UpdateCvePriority(mock.Anything).Return(int64(0), nil)
	mock.InOrder(bulkUpdate.Call, updatePriority.Call)

	f := kev.NewFetcher(q, testLogger(), kev.NewCisaClient(srv.URL))
	require.NoError(t, f.Sync(context.Background()))
}
