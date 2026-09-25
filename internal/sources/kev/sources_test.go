package kev_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nais/v13s/internal/config"
	sqldatabase "github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type staticSource struct {
	name       string
	assertions []kev.Assertion
	err        error
}

func (s staticSource) Name() string { return s.name }

func (s staticSource) Fetch(context.Context) ([]kev.Assertion, error) {
	return s.assertions, s.err
}

func TestFetcher_Sync_MergesSources(t *testing.T) {
	cisa := staticSource{name: kev.SourceCISA, assertions: []kev.Assertion{
		{CveID: "CVE-2021-44228", KnownRansomware: true},
		{CveID: "CVE-2023-0001"},
	}}
	enisa := staticSource{name: kev.SourceENISA, assertions: []kev.Assertion{
		{CveID: "CVE-2021-44228", KnownRansomware: false},
		{CveID: "CVE-2015-7501"},
		{CveID: "CVE-2023-0001", KnownRansomware: true},
		{CveID: "CVE-2023-0001", KnownRansomware: true},
	}}

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             []string{"CVE-2015-7501", "CVE-2021-44228", "CVE-2023-0001"},
		KnownRansomwareUse: []bool{false, true, true},
		SourceCveIds:       []string{"CVE-2015-7501", "CVE-2021-44228", "CVE-2021-44228", "CVE-2023-0001", "CVE-2023-0001"},
		SourceNames:        []string{"enisa", "cisa", "enisa", "cisa", "enisa"},
		Complete:           true,
	}).Return(int64(3), nil).Once()
	q.EXPECT().UpdateCvePriority(mock.Anything).Return(int64(0), nil).Once()

	require.NoError(t, kev.NewFetcher(q, testLogger(), cisa, enisa).Sync(context.Background()))
}

func TestFetcher_Sync_FailedSourceKeepsPreviousData(t *testing.T) {
	cisa := staticSource{name: kev.SourceCISA, assertions: []kev.Assertion{{CveID: "CVE-2021-44228"}}}
	enisa := staticSource{name: kev.SourceENISA, err: errors.New("unavailable")}

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             []string{"CVE-2021-44228"},
		KnownRansomwareUse: []bool{false},
		SourceCveIds:       []string{"CVE-2021-44228"},
		SourceNames:        []string{"cisa"},
		Complete:           false,
	}).Return(int64(1), nil).Once()
	q.EXPECT().UpdateCvePriority(mock.Anything).Return(int64(0), nil).Once()

	err := kev.NewFetcher(q, testLogger(), cisa, enisa).Sync(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enisa")
}

func TestFetcher_Sync_AllSourcesFail(t *testing.T) {
	cisa := staticSource{name: kev.SourceCISA, err: errors.New("unavailable")}

	q := mockquerier.NewMockQuerier(t)

	err := kev.NewFetcher(q, testLogger(), cisa).Sync(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cisa")
}

func TestFetcher_Sync_EmptySourceTreatedAsFailed(t *testing.T) {
	cisa := staticSource{name: kev.SourceCISA, assertions: []kev.Assertion{{CveID: "CVE-2021-44228"}}}
	enisa := staticSource{name: kev.SourceENISA}

	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().BulkUpdateKevData(mock.Anything, sqldatabase.BulkUpdateKevDataParams{
		CveIds:             []string{"CVE-2021-44228"},
		KnownRansomwareUse: []bool{false},
		SourceCveIds:       []string{"CVE-2021-44228"},
		SourceNames:        []string{"cisa"},
		Complete:           false,
	}).Return(int64(1), nil).Once()
	q.EXPECT().UpdateCvePriority(mock.Anything).Return(int64(0), nil).Once()

	err := kev.NewFetcher(q, testLogger(), cisa, enisa).Sync(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "enisa returned no entries")
}

func TestFetcher_Sync_NoSources(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	require.NoError(t, kev.NewFetcher(q, testLogger()).Sync(context.Background()))
}

func TestSourcesFromConfig(t *testing.T) {
	names := func(sources []kev.Source) []string {
		var n []string
		for _, s := range sources {
			n = append(n, s.Name())
		}
		return n
	}

	cfg := config.KevConfig{CatalogURL: "https://cisa", EnisaURL: "https://enisa", VulnCheckToken: "token"}
	assert.Equal(t, []string{"cisa", "enisa"}, names(kev.SourcesFromConfig(cfg)), "VulnCheck stays off unless enabled")

	cfg.VulnCheckEnabled = true
	assert.Equal(t, []string{"cisa", "enisa", "vulncheck"}, names(kev.SourcesFromConfig(cfg)))
	require.NoError(t, cfg.Validate())

	cfg.VulnCheckToken = ""
	assert.Error(t, cfg.Validate(), "VulnCheck enabled without a token must be rejected at startup")
}

func TestEnisaClient_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"cveID": "CVE-2015-7501", "euvdID": "EUVD-1", "exploitationType": "unknown"},
			{"cveID": "CVE-2024-0001", "euvdID": "EUVD-2", "exploitationType": "Ransomware"},
			{"cveID": null, "euvdID": "EUVD-3", "exploitationType": "APT"},
			{"cveID": "CVE-2024-0002", "euvdID": "EUVD-4", "exploitationType": ["unknown"]},
			{"cveID": "CVE-2024-0003", "euvdID": "EUVD-5", "exploitationType": ["APT", "ransomware"]},
			{"cveID": "CVE-2024-0004", "euvdID": "EUVD-6"}
		]`))
	}))
	defer srv.Close()

	assertions, err := kev.NewEnisaClient(srv.URL).Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []kev.Assertion{
		{CveID: "CVE-2015-7501"},
		{CveID: "CVE-2024-0001", KnownRansomware: true},
		{CveID: "CVE-2024-0002"},
		{CveID: "CVE-2024-0003", KnownRansomware: true},
		{CveID: "CVE-2024-0004"},
	}, assertions)
}

func zipArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func newVulnCheckServer(t *testing.T, archive []byte, checksum string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/backup/vulncheck-kev":
			if r.Header.Get("Authorization") != "Bearer token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"url":"` + srv.URL + `/download/kev.zip?X-Signature=secret","sha256":"` + checksum + `"}]}`))
		case "/download/kev.zip":
			_, _ = w.Write(archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestVulnCheckClient_Fetch(t *testing.T) {
	archive := zipArchive(t, map[string]string{
		"kev-1.json": `[{"cve":["CVE-2024-0001","CVE-2024-0002"],"knownRansomwareCampaignUse":"known"}]`,
		"kev-2.json": `{"cve":["CVE-2024-0003"],"knownRansomwareCampaignUse":"Unknown"}
{"cve":["CVE-2024-0004"]}`,
		"README.txt": "ignored",
	})
	srv := newVulnCheckServer(t, archive, sha256Hex(archive))

	assertions, err := kev.NewVulnCheckClient(srv.URL, "token").Fetch(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []kev.Assertion{
		{CveID: "CVE-2024-0001", KnownRansomware: true},
		{CveID: "CVE-2024-0002", KnownRansomware: true},
		{CveID: "CVE-2024-0003"},
		{CveID: "CVE-2024-0004"},
	}, assertions)
}

func TestVulnCheckClient_Fetch_ChecksumMismatch(t *testing.T) {
	archive := zipArchive(t, map[string]string{"kev.json": `[]`})
	srv := newVulnCheckServer(t, archive, sha256Hex([]byte("something else")))

	_, err := kev.NewVulnCheckClient(srv.URL, "token").Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestVulnCheckClient_Fetch_TruncatedArray(t *testing.T) {
	archive := zipArchive(t, map[string]string{"kev.json": `[{"cve":["CVE-2024-0001"]}`})
	srv := newVulnCheckServer(t, archive, sha256Hex(archive))

	_, err := kev.NewVulnCheckClient(srv.URL, "token").Fetch(context.Background())
	require.Error(t, err)
}

func TestVulnCheckClient_Fetch_TrailingDataAfterArray(t *testing.T) {
	for name, content := range map[string]string{
		"truncated object": `[{"cve":["CVE-2024-0001"]}] {`,
		"second array":     `[{"cve":["CVE-2024-0001"]}] []`,
	} {
		t.Run(name, func(t *testing.T) {
			archive := zipArchive(t, map[string]string{"kev.json": content})
			srv := newVulnCheckServer(t, archive, sha256Hex(archive))

			_, err := kev.NewVulnCheckClient(srv.URL, "token").Fetch(context.Background())
			require.Error(t, err)
		})
	}
}

func TestVulnCheckClient_Fetch_Unauthorized(t *testing.T) {
	srv := newVulnCheckServer(t, nil, "")

	_, err := kev.NewVulnCheckClient(srv.URL, "wrong").Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}
