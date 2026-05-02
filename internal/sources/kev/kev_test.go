package kev_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqldatabase "github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T, catalog kev.Catalog, etag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
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

func TestFetchCatalog_ParsesResponse(t *testing.T) {
	srv := newTestServer(t, sampleCatalog(), "\"abc123\"")
	defer srv.Close()

	client := kev.NewClientWithURL(srv.URL)
	result, err := client.FetchCatalog(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "CISA KEV", result.Catalog.Title)
	assert.Equal(t, "2024.01.01", result.Catalog.CatalogVersion)
	assert.Len(t, result.Catalog.Vulnerabilities, 2)
	assert.Equal(t, "\"abc123\"", result.ETag)
}

func TestFetchCatalog_NoETag(t *testing.T) {
	srv := newTestServer(t, sampleCatalog(), "")
	defer srv.Close()

	client := kev.NewClientWithURL(srv.URL)
	result, err := client.FetchCatalog(context.Background())
	require.NoError(t, err)
	assert.Empty(t, result.ETag)
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

func TestFetchCatalog_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := kev.NewClientWithURL(srv.URL)
	_, err := client.FetchCatalog(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestFetchCatalog_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	client := kev.NewClientWithURL(srv.URL)
	_, err := client.FetchCatalog(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding KEV catalog")
}

func TestFetcher_Sync_SkipsOnMatchingETag(t *testing.T) {
	const etag = "\"same-etag\""
	srv := newTestServer(t, sampleCatalog(), etag)
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(&sqldatabase.GetKevSyncStateRow{
		Etag:     etag,
		SyncedAt: pgtype.Timestamptz{Valid: true},
	}, nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}

func TestFetcher_Sync_UpdatesOnNewETag(t *testing.T) {
	const oldETag = "\"old\""
	const newETag = "\"new\""
	srv := newTestServer(t, sampleCatalog(), newETag)
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(&sqldatabase.GetKevSyncStateRow{
		Etag:     oldETag,
		SyncedAt: pgtype.Timestamptz{Valid: true},
	}, nil)
	q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             []string{"CVE-2021-44228", "CVE-2023-1234"},
		KnownRansomwareUse: []bool{true, false},
	}).Return(nil)
	q.EXPECT().UpsertKevSyncState(mock.Anything, newETag).Return(nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}

func TestFetcher_Sync_FirstRunNoState(t *testing.T) {
	const etag = "\"first\""
	srv := newTestServer(t, sampleCatalog(), etag)
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(nil, pgx.ErrNoRows)
	q.EXPECT().BulkUpdateKevData(mock.Anything, mock.Anything).Return(nil)
	q.EXPECT().UpsertKevSyncState(mock.Anything, etag).Return(nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}

func TestFetcher_Sync_ServerNoETag_AlwaysUpdates(t *testing.T) {
	srv := newTestServer(t, sampleCatalog(), "")
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(&sqldatabase.GetKevSyncStateRow{
		Etag: "",
	}, nil)
	q.EXPECT().BulkUpdateKevData(mock.Anything, mock.Anything).Return(nil)
	q.EXPECT().UpsertKevSyncState(mock.Anything, "").Return(nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/kev_catalog.json")
	require.NoError(t, err)
	return b
}

func newFixtureServer(t *testing.T, etag string) *httptest.Server {
	t.Helper()
	raw := loadFixture(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
}

func TestFetchCatalog_RealFixture_ParsesCorrectly(t *testing.T) {
	srv := newFixtureServer(t, "\"fixture-etag\"")
	defer srv.Close()

	client := kev.NewClientWithURL(srv.URL)
	result, err := client.FetchCatalog(context.Background())
	require.NoError(t, err)

	catalog := result.Catalog

	assert.Greater(t, catalog.Count, 0)
	assert.Len(t, catalog.Vulnerabilities, catalog.Count)

	for i, v := range catalog.Vulnerabilities {
		assert.NotEmpty(t, v.CveID, "entry %d has empty CveID", i)
	}

	known := 0
	for _, v := range catalog.Vulnerabilities {
		if v.KnownRansomware() {
			known++
		}
	}
	assert.Greater(t, known, 0)

	t.Logf("fixture: %d total entries, %d with known ransomware use (version %s)",
		catalog.Count, known, catalog.CatalogVersion)
}

func TestFetcher_Sync_RealFixture(t *testing.T) {
	const etag = "\"fixture-etag\""
	srv := newFixtureServer(t, etag)
	defer srv.Close()

	raw := loadFixture(t)
	var catalog kev.Catalog
	require.NoError(t, json.Unmarshal(raw, &catalog))

	expectedIDs := make([]string, len(catalog.Vulnerabilities))
	expectedRansomware := make([]bool, len(catalog.Vulnerabilities))
	for i, v := range catalog.Vulnerabilities {
		expectedIDs[i] = v.CveID
		expectedRansomware[i] = v.KnownRansomware()
	}

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(nil, pgx.ErrNoRows)
	q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             expectedIDs,
		KnownRansomwareUse: expectedRansomware,
	}).Return(nil)
	q.EXPECT().UpsertKevSyncState(mock.Anything, etag).Return(nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}

func TestFetcher_Sync_RealFixture_SkipsOnSameETag(t *testing.T) {
	const etag = "\"fixture-etag\""
	srv := newFixtureServer(t, etag)
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetKevSyncState(mock.Anything).Return(&sqldatabase.GetKevSyncStateRow{
		Etag:     etag,
		SyncedAt: pgtype.Timestamptz{Valid: true},
	}, nil)

	f := kev.NewFetcherWithClient(kev.NewClientWithURL(srv.URL), q, testLogger())
	err := f.Sync(context.Background())
	require.NoError(t, err)
}
