package osv_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	sqldatabase "github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return logrus.NewEntry(l)
}

func newVulnServer(t *testing.T, records map[string]*osv.VulnRecord) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/vulns/"):]
		rec, ok := records[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok || rec == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 5, "message": "Bug not found."})
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(rec))
	}))
}

// sampleRecords returns CVE/GHSA records mirroring real OSV behaviour for use in tests.
func sampleRecords() map[string]*osv.VulnRecord {
	return map[string]*osv.VulnRecord{
		"CVE-2021-44228": {
			ID:      "CVE-2021-44228",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
		},
		"GHSA-jfh8-c2jp-5v3q": {
			ID:      "GHSA-jfh8-c2jp-5v3q",
			Aliases: []string{"CVE-2021-44228"},
			Affected: []osv.Affected{
				{
					Package: osv.AffectedPackage{
						Ecosystem: "Maven",
						Name:      "org.apache.logging.log4j:log4j-core",
						Purl:      "pkg:maven/org.apache.logging.log4j/log4j-core",
					},
					Ranges: []osv.Range{
						{Type: "SEMVER", Events: []osv.Event{{Introduced: "2.0.0"}, {Fixed: "2.15.0"}}},
					},
				},
			},
		},
		// CVE record with no aliases and no affected — no fix version.
		"CVE-9999-9999": {
			ID: "CVE-9999-9999",
		},
		// Multi-branch record mirrors CVE-2025-24813 (tomcat): three Affected entries, one per branch.
		"GHSA-tomcat-multibranch": {
			ID: "GHSA-tomcat-multibranch",
			Affected: []osv.Affected{
				{
					Package: osv.AffectedPackage{
						Ecosystem: "Maven",
						Purl:      "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core",
					},
					Ranges: []osv.Range{
						{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "11.0.0-M1"}, {Fixed: "11.0.3"}}},
					},
				},
				{
					Package: osv.AffectedPackage{
						Ecosystem: "Maven",
						Purl:      "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core",
					},
					Ranges: []osv.Range{
						{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "10.1.0-M1"}, {Fixed: "10.1.35"}}},
					},
				},
				{
					Package: osv.AffectedPackage{
						Ecosystem: "Maven",
						Purl:      "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core",
					},
					Ranges: []osv.Range{
						{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "9.0.0.M1"}, {Fixed: "9.0.99"}}},
					},
				},
			},
		},
	}
}

func mustUUID(s string) pgtype.UUID {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		panic(err)
	}
	return u
}

func TestFetchVuln_ReturnsRecord(t *testing.T) {
	srv := newVulnServer(t, sampleRecords())
	defer srv.Close()

	client := osv.NewClientWithURL(srv.URL)
	rec, err := client.FetchVuln(context.Background(), "CVE-2021-44228")
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, "CVE-2021-44228", rec.ID)
	assert.Equal(t, []string{"GHSA-jfh8-c2jp-5v3q"}, rec.Aliases)
	// CVE record itself has no affected — ecosystem data lives in the GHSA alias.
	assert.Empty(t, rec.Affected)
}

func TestFetchVuln_NotFound_ReturnsNil(t *testing.T) {
	srv := newVulnServer(t, sampleRecords())
	defer srv.Close()

	client := osv.NewClientWithURL(srv.URL)
	rec, err := client.FetchVuln(context.Background(), "CVE-0000-0000") // not in map
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestFetchVuln_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := osv.NewClientWithURL(srv.URL)
	_, err := client.FetchVuln(context.Background(), "CVE-2021-44228")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestFetchVuln_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid"))
	}))
	defer srv.Close()

	client := osv.NewClientWithURL(srv.URL)
	_, err := client.FetchVuln(context.Background(), "CVE-2021-44228")
	require.Error(t, err)
}

func TestFixVersionForPurl(t *testing.T) {
	records := sampleRecords()

	tests := []struct {
		name     string
		record   *osv.VulnRecord
		purl     string
		expected string
	}{
		{
			name:     "semver match — returns fixed version",
			record:   records["GHSA-jfh8-c2jp-5v3q"],
			purl:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
			expected: "2.15.0",
		},
		{
			name:     "match ignores qualifiers",
			record:   records["GHSA-jfh8-c2jp-5v3q"],
			purl:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0?type=jar",
			expected: "2.15.0",
		},
		{
			name:     "purl mismatch — empty string",
			record:   records["GHSA-jfh8-c2jp-5v3q"],
			purl:     "pkg:maven/org.apache.httpcomponents/httpclient@4.0.1",
			expected: "",
		},
		{
			name: "no purl in affected — empty string",
			record: &osv.VulnRecord{
				ID: "CVE-2099-0001",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Ecosystem: "Go", Name: "example.com/foo"},
						Ranges: []osv.Range{
							{Type: "SEMVER", Events: []osv.Event{{Fixed: "1.0.0"}}},
						},
					},
				},
			},
			purl:     "pkg:golang/example.com/foo@0.9.0",
			expected: "",
		},
		{
			name: "semver preferred over ecosystem",
			record: &osv.VulnRecord{
				ID: "CVE-2099-0002",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:npm/foo"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Fixed: "eco-1.0"}}},
							{Type: "SEMVER", Events: []osv.Event{{Fixed: "sem-2.0"}}},
						},
					},
				},
			},
			purl:     "pkg:npm/foo@1.0.0",
			expected: "sem-2.0",
		},
		{
			name: "git range used when no semver/ecosystem",
			record: &osv.VulnRecord{
				ID: "CVE-2099-0003",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:generic/bar"},
						Ranges: []osv.Range{
							{Type: "GIT", Events: []osv.Event{
								{Introduced: "abc"},
								{Fixed: "def"},
							}},
						},
					},
				},
			},
			purl:     "pkg:generic/bar@0.1",
			expected: "def",
		},
		{
			name:     "multi-branch: picks minimum fix > installed (10.1.x branch)",
			record:   sampleRecords()["GHSA-tomcat-multibranch"],
			purl:     "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.24",
			expected: "10.1.35",
		},
		{
			name:     "multi-branch: picks minimum fix > installed (11.0.x branch)",
			record:   sampleRecords()["GHSA-tomcat-multibranch"],
			purl:     "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.1",
			expected: "11.0.3",
		},
		{
			name:     "multi-branch: picks minimum fix > installed (9.0.x branch)",
			record:   sampleRecords()["GHSA-tomcat-multibranch"],
			purl:     "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.50",
			expected: "9.0.99",
		},
		{
			name:     "multi-branch: installed already past branch fix — picks next branch fix",
			record:   sampleRecords()["GHSA-tomcat-multibranch"],
			purl:     "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.36",
			expected: "11.0.3",
		},
		{
			// vite 5.x: installed=5.2.12, OSV fixes: 4.5.10, 5.4.15, 6.0.12, 6.1.2, 6.2.3
			name: "vite 5.x branch: picks 5.4.15 not 6.x", record: &osv.VulnRecord{
				ID: "GHSA-vite",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:npm/vite"},
						Ranges: []osv.Range{
							{Type: "SEMVER", Events: []osv.Event{
								{Fixed: "4.5.10"},
								{Fixed: "5.4.15"},
								{Fixed: "6.0.12"},
								{Fixed: "6.1.2"},
								{Fixed: "6.2.3"},
							}},
						},
					},
				},
			},
			purl:     "pkg:npm/vite@5.2.12",
			expected: "5.4.15",
		},
		{
			// netty .Final suffix: two separate Affected entries (one per branch).
			// installed=4.2.6.Final should pick 4.2.10.Final, not 4.1.132.Final.
			name: "dotFinal suffix: picks correct branch fix",
			record: &osv.VulnRecord{
				ID: "GHSA-netty-multibranch",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/io.netty/netty-codec-http"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "4.1.132.Final"}}},
						},
					},
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/io.netty/netty-codec-http"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "4.2.0.Alpha1"}, {Fixed: "4.2.10.Final"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/io.netty/netty-codec-http@4.2.6.Final",
			expected: "4.2.10.Final",
		},
		{
			// jackson-databind 2.13.x: installed=2.13.3, fix=2.13.4.2 (4-part numeric).
			// The 2.12.x branch fix (2.12.7.1) must be rejected.
			name: "four-part numeric: picks 2.13.x branch fix not 2.12.x",
			record: &osv.VulnRecord{
				ID: "GHSA-jackson-multibranch",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "2.4.0-rc1"}, {Fixed: "2.12.7.1"}}},
						},
					},
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "2.13.0"}, {Fixed: "2.13.4.2"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.3",
			expected: "2.13.4.2",
		},
		{
			// snappy-java: installed=1.1.7.3, fix=1.1.10.1 (both 4-part).
			name: "four-part numeric both installed and fixed",
			record: &osv.VulnRecord{
				ID: "GHSA-snappy",
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/org.xerial.snappy/snappy-java"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.1.10.1"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/org.xerial.snappy/snappy-java@1.1.7.3",
			expected: "1.1.10.1",
		},
		{
			// mssql plain version (no jre suffix) against jre-only ranges:
			// 13.2.1 plain is not in range [13.2.0.jre11, 13.2.1.jre11) — no fix match.
			name: "jre11 suffix: plain installed version does not match jre-only range",
			record: &osv.VulnRecord{
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.microsoft.sqlserver/mssql-jdbc"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "8.3.0.jre11-preview"}, {Fixed: "10.2.4.jre11"}}},
						},
					},
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.microsoft.sqlserver/mssql-jdbc"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "13.2.0.jre11"}, {Fixed: "13.2.1.jre11"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/com.microsoft.sqlserver/mssql-jdbc@13.2.1",
			expected: "",
		},
		{
			// guava -jre installed, OSV fix is -android classifier: fix classifier should
			// be substituted to match the installed -jre classifier.
			name: "classifier substitution: -android fix becomes -jre for -jre installed",
			record: &osv.VulnRecord{
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.google.guava/guava"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "32.0.0-android"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/com.google.guava/guava@30.0-jre",
			expected: "32.0.0-jre",
		},
		{
			// guava -android installed: fix classifier already matches, no substitution.
			name: "classifier substitution: no change when classifiers already match",
			record: &osv.VulnRecord{
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:maven/com.google.guava/guava"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "32.0.0-android"}}},
						},
					},
				},
			},
			purl:     "pkg:maven/com.google.guava/guava@30.0-android",
			expected: "32.0.0-android",
		},
		{
			// golang v-prefix: installed version has v-prefix, OSV fix version does not — v should be added.
			name: "golang v-prefix: fix version gets v prefix to match installed",
			record: &osv.VulnRecord{
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:golang/github.com/jackc/pgx/v5"},
						Ranges: []osv.Range{
							{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: "5.9.2"}}},
						},
					},
				},
			},
			purl:     "pkg:golang/github.com/jackc/pgx/v5@v5.5.4",
			expected: "v5.9.2",
		},
		{
			// NuGet case-insensitive purl match: DT sends NETCore, OSV has NetCore.
			name: "nuget case-insensitive purl match",
			record: &osv.VulnRecord{
				Affected: []osv.Affected{
					{
						Package: osv.AffectedPackage{Purl: "pkg:nuget/Microsoft.NetCore.App.Runtime.linux-musl-x64"},
						Ranges: []osv.Range{
							{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "8.0.0"}, {Fixed: "8.0.26"}}},
						},
					},
				},
			},
			purl:     "pkg:nuget/Microsoft.NETCore.App.Runtime.linux-musl-x64@8.0.24",
			expected: "8.0.26",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := osv.FixVersionForPurl(tc.record, tc.purl)
			assert.Equal(t, tc.expected, got)
		})
	}
}

var (
	testUUID1 = mustUUID("00000000-0000-0000-0000-000000000001")
	testUUID2 = mustUUID("00000000-0000-0000-0000-000000000002")
)

// expectLock sets up the advisory lock/unlock expectations that every successful sync needs.
func expectLock(q *mockquerier.MockQuerier) {
	q.EXPECT().TryAdvisoryLock(mock.Anything, osv.OsvSyncLockKey).Return(true, nil)
	q.EXPECT().AdvisoryUnlock(mock.Anything, osv.OsvSyncLockKey).Return(nil)
}

func TestFetcher_Sync_WritesFixVersions(t *testing.T) {
	srv := newVulnServer(t, sampleRecords())
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-2021-44228", Package: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
			{ID: testUUID2, CveID: "CVE-9999-9999", Package: "pkg:npm/unknown@1.0.0"},
		}, nil)
	q.EXPECT().
		BulkUpdateFixVersions(mock.Anything, sqldatabase.BulkUpdateFixVersionsParams{
			VulnerabilityIds: []pgtype.UUID{testUUID1},
			FixVersions:      []string{"2.15.0"},
		}).
		Return(int64(1), nil)
	q.EXPECT().
		BulkClearFixVersions(mock.Anything, []pgtype.UUID{testUUID2}).
		Return(int64(0), nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_FetchesGHSAAlias(t *testing.T) {
	srv := newVulnServer(t, sampleRecords())
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-2021-44228", Package: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
		}, nil)
	q.EXPECT().
		BulkUpdateFixVersions(mock.Anything, sqldatabase.BulkUpdateFixVersionsParams{
			VulnerabilityIds: []pgtype.UUID{testUUID1},
			FixVersions:      []string{"2.15.0"},
		}).
		Return(int64(1), nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_404WithAliasHint(t *testing.T) {
	ghsaRecord := &osv.VulnRecord{
		ID:      "GHSA-4vgm-c2wm-63mw",
		Aliases: []string{"CVE-2026-26130"},
		Affected: []osv.Affected{
			{
				Package: osv.AffectedPackage{
					Ecosystem: "NuGet",
					Name:      "Microsoft.AspNetCore.App.Runtime.linux-musl-x64",
					Purl:      "pkg:nuget/Microsoft.AspNetCore.App.Runtime.linux-musl-x64",
				},
				Ranges: []osv.Range{
					{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "8.0.0"}, {Fixed: "8.0.25"}}},
				},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/vulns/"):]
		w.Header().Set("Content-Type", "application/json")
		switch id {
		case "CVE-2026-26130":
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    5,
				"message": "Bug not found, but the following aliases were: GHSA-4vgm-c2wm-63mw",
			})
		case "GHSA-4vgm-c2wm-63mw":
			_ = json.NewEncoder(w).Encode(ghsaRecord)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 5, "message": "Bug not found."})
		}
	}))
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-2026-26130", Package: "pkg:nuget/Microsoft.AspNetCore.App.Runtime.linux-musl-x64@8.0.24"},
		}, nil)
	q.EXPECT().
		BulkUpdateFixVersions(mock.Anything, sqldatabase.BulkUpdateFixVersionsParams{
			VulnerabilityIds: []pgtype.UUID{testUUID1},
			FixVersions:      []string{"8.0.25"},
		}).
		Return(int64(1), nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_EmptyDB(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{}, nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL("http://unused"), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_AlreadyLocked_Skips(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().TryAdvisoryLock(mock.Anything, osv.OsvSyncLockKey).Return(false, nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL("http://unused"), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
	// No GetVulnerabilitiesForOsvEnrichment call expected — mock will fail if it is called.
}

func TestFetcher_Sync_NoFixVersionsFound(t *testing.T) {
	srv := newVulnServer(t, map[string]*osv.VulnRecord{})
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-9999-9999", Package: "pkg:npm/foo@1.0.0"},
		}, nil)
	q.EXPECT().
		BulkClearFixVersions(mock.Anything, []pgtype.UUID{testUUID1}).
		Return(int64(0), nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_ClientError_Warns_Continues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-2021-44228", Package: "pkg:maven/log4j/log4j@2.14.0"},
		}, nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))
}

func TestFetcher_Sync_WorkerPoolConcurrency(t *testing.T) {
	var fetchCount atomic.Int32
	records := sampleRecords()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		id := r.URL.Path[len("/vulns/"):]
		rec, ok := records[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok || rec == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 5, "message": "Bug not found."})
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(rec))
	}))
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().
		GetVulnerabilitiesForOsvEnrichment(mock.Anything).
		Return([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			{ID: testUUID1, CveID: "CVE-2021-44228", Package: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
			{ID: testUUID2, CveID: "CVE-9999-9999", Package: "pkg:npm/unknown@1.0.0"},
		}, nil)
	q.EXPECT().BulkUpdateFixVersions(mock.Anything, mock.Anything).Return(int64(1), nil)
	q.EXPECT().BulkClearFixVersions(mock.Anything, mock.Anything).Return(int64(0), nil)

	f := osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger())
	require.NoError(t, f.Sync(context.Background()))

	// CVE-2021-44228 + its GHSA alias + CVE-9999-9999 = 3 fetches.
	assert.EqualValues(t, 3, fetchCount.Load())
}

// newFixServer returns a test server that returns a fixed OSV record for every CVE ID.
func newFixServer(t *testing.T, fixVersion string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/vulns/"):]
		w.Header().Set("Content-Type", "application/json")
		rec := &osv.VulnRecord{
			ID: id,
			Affected: []osv.Affected{
				{
					Package: osv.AffectedPackage{Purl: fmt.Sprintf("pkg:npm/%s", id)},
					Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: fixVersion}}}},
				},
			},
		}
		require.NoError(t, json.NewEncoder(w).Encode(rec))
	}))
}

func TestFetcher_Persist_BatchesUpdates(t *testing.T) {
	n := osv.BatchSize + 1
	rows := make([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow, n)
	for i := range n {
		cveID := fmt.Sprintf("CVE-2024-%04d", i)
		u := mustUUID(fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		rows[i] = &sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			ID:      u,
			CveID:   cveID,
			Package: fmt.Sprintf("pkg:npm/%s@0.9.0", cveID),
		}
	}

	srv := newFixServer(t, "1.0.0")
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().GetVulnerabilitiesForOsvEnrichment(mock.Anything).Return(rows, nil)

	var batchSizes []int
	q.EXPECT().
		BulkUpdateFixVersions(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, p sqldatabase.BulkUpdateFixVersionsParams) (int64, error) {
			batchSizes = append(batchSizes, len(p.VulnerabilityIds))
			return int64(len(p.VulnerabilityIds)), nil
		}).
		Times(2)

	require.NoError(t, osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger()).Sync(context.Background()))
	require.Len(t, batchSizes, 2)
	assert.Equal(t, osv.BatchSize, batchSizes[0])
	assert.Equal(t, 1, batchSizes[1])
}

func TestFetcher_Persist_BatchesClears(t *testing.T) {
	n := osv.BatchSize + 1
	rows := make([]*sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow, n)
	for i := range n {
		u := mustUUID(fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		rows[i] = &sqldatabase.GetVulnerabilitiesForOsvEnrichmentRow{
			ID:      u,
			CveID:   fmt.Sprintf("CVE-9999-%04d", i),
			Package: fmt.Sprintf("pkg:npm/unknown-%d@1.0.0", i),
		}
	}

	srv := newVulnServer(t, map[string]*osv.VulnRecord{})
	defer srv.Close()

	q := mockquerier.NewMockQuerier(t)
	expectLock(q)
	q.EXPECT().GetVulnerabilitiesForOsvEnrichment(mock.Anything).Return(rows, nil)

	var batchSizes []int
	q.EXPECT().
		BulkClearFixVersions(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, ids []pgtype.UUID) (int64, error) {
			batchSizes = append(batchSizes, len(ids))
			return int64(0), nil
		}).
		Times(2)

	require.NoError(t, osv.NewFetcherWithClient(osv.NewClientWithURL(srv.URL), q, testLogger()).Sync(context.Background()))
	require.Len(t, batchSizes, 2)
	assert.Equal(t, osv.BatchSize, batchSizes[0])
	assert.Equal(t, 1, batchSizes[1])
}
