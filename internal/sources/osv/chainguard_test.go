package osv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	Querier "github.com/nais/v13s/internal/mocks/Querier"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testCGA  = "CGA-fjmw-f657-w678"
	testPurl = "pkg:apk/chainguard/glibc-2.44@2.44-r11?arch=x86_64&distro=20230214"
)

func chainguardRecord(events ...Event) *VulnRecord {
	return &VulnRecord{
		ID: testCGA,
		Affected: []Affected{{
			Package: AffectedPackage{
				Ecosystem: "Chainguard",
				Name:      "glibc-2.44",
				Purl:      "pkg:apk/chainguard/glibc-2.44?arch=x86_64",
			},
			Ranges: []Range{{Type: rangeTypeEcosystem, Events: events}},
		}},
	}
}

type chainguardRevisionCase struct {
	name string
	purl string
	fix  string
	miss MissReason
}

type chainguardRangeCase struct {
	name   string
	events []Event
	fix    string
	miss   MissReason
}

type chainguardRecordCase struct {
	name   string
	change func(*VulnRecord)
}

func TestChainguardFixAPKRevisions(t *testing.T) {
	for _, tt := range []chainguardRevisionCase{
		{"vulnerable", strings.Replace(testPurl, "r11", "r6", 1), "2.44-r8", MissNone},
		{"fixed boundary", strings.Replace(testPurl, "r11", "r8", 1), "", MissInstalledPastFix},
		{"double digit revision", strings.Replace(testPurl, "r11", "r10", 1), "", MissInstalledPastFix},
		{"reported installed revision", testPurl, "", MissInstalledPastFix},
		{"other architecture", strings.Replace(testPurl, "x86_64", "aarch64", 1), "", MissPackageNotListed},
		{"missing architecture", "pkg:apk/chainguard/glibc-2.44@2.44-r11", "", MissUnknown},
		{"other package", strings.Replace(testPurl, "glibc-2.44", "ld-linux-2.44", 1), "", MissPackageNotListed},
		{"other ecosystem", strings.Replace(testPurl, "/chainguard/", "/alpine/", 1), "", MissUnknown},
		{"invalid installed version", strings.Replace(testPurl, "2.44-r11", "2.44-rbroken", 1), "", MissUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			record := chainguardRecord(Event{Introduced: "0"}, Event{Fixed: "2.44-r8"})
			fix, miss := chainguardFix(record, testCGA, tt.purl)
			require.Equal(t, tt.fix, fix)
			require.Equal(t, tt.miss, miss)
		})
	}
}

func TestChainguardFixConservativeRanges(t *testing.T) {
	for _, tt := range []chainguardRangeCase{
		{"no patch", []Event{{Introduced: "0"}}, "", MissNoFixUpstream},
		{"reintroduced", []Event{{Introduced: "0"}, {Fixed: "2.44-r8"}, {Introduced: "2.44-r10"}}, "", MissNoFixUpstream},
		{"reintroduced with later fix", []Event{{Introduced: "0"}, {Fixed: "2.44-r8"}, {Introduced: "2.44-r10"}, {Fixed: "2.44-r12"}}, "2.44-r12", MissNone},
		{"invalid fixed version", []Event{{Introduced: "0"}, {Fixed: "broken"}}, "", MissUnknown},
		{"invalid revision", []Event{{Introduced: "0"}, {Fixed: "2.44-rbroken"}}, "", MissUnknown},
		{"missing introduction", []Event{{Fixed: "2.44-r8"}}, "", MissUnknown},
		{"reversed interval", []Event{{Introduced: "2.44-r12"}, {Fixed: "2.44-r8"}}, "", MissUnknown},
		{"empty interval", []Event{{Introduced: "2.44-r8"}, {Fixed: "2.44-r8"}}, "", MissUnknown},
		{"ambiguous event", []Event{{Introduced: "0", Fixed: "2.44-r8"}}, "", MissUnknown},
		{"empty event", []Event{{Introduced: "0"}, {Fixed: "2.44-r8"}, {}}, "", MissUnknown},
		{"last affected without fix", []Event{{Introduced: "0"}, {LastAffected: "2.44-r7"}}, "", MissUnknown},
		{"limit not a fix", []Event{{Introduced: "0"}, {Limit: "2.44-r8"}}, "", MissUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fix, miss := chainguardFix(chainguardRecord(tt.events...), testCGA, testPurl)
			require.Equal(t, tt.fix, fix)
			require.Equal(t, tt.miss, miss)
		})
	}
}

func TestChainguardFixRejectsUntrustedRecords(t *testing.T) {
	for _, tt := range []chainguardRecordCase{
		{"wrong advisory", func(r *VulnRecord) { r.ID = "CGA-q52v-g232-2h9m" }},
		{"withdrawn", func(r *VulnRecord) { now := time.Now(); r.Withdrawn = &now }},
		{"wrong ecosystem", func(r *VulnRecord) { r.Affected[0].Package.Ecosystem = "Wolfi" }},
		{"wrong PURL", func(r *VulnRecord) { r.Affected[0].Package.Purl = "pkg:apk/chainguard/other?arch=x86_64" }},
		{"unqualified source", func(r *VulnRecord) { r.Affected[0].Package.Purl = "pkg:apk/chainguard/glibc-2.44" }},
		{"unknown range", func(r *VulnRecord) { r.Affected[0].Ranges[0].Type = rangeTypeGit }},
		{"empty ranges", func(r *VulnRecord) { r.Affected[0].Ranges = nil }},
		{"affected version list", func(r *VulnRecord) { r.Affected[0].Versions = []string{"2.44-r11"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			record := chainguardRecord(Event{Introduced: "0"}, Event{Fixed: "2.44-r8"})
			tt.change(record)
			_, miss := chainguardFix(record, testCGA, testPurl)
			require.NotEqual(t, MissInstalledPastFix, miss)
		})
	}
}

type chainguardTransport func(*http.Request) (*http.Response, error)

func (f chainguardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestChainguardSyncRevalidatesCorrections(t *testing.T) {
	ctx := context.Background()
	q := Querier.NewMockQuerier(t)
	log, _ := logrustest.NewNullLogger()
	f := NewFetcherWithQuerier(NewClientWithURL(""), q, log.WithField("test", true)).WithChainguard(true)
	body, err := json.Marshal(chainguardRecord(Event{Introduced: "0"}, Event{Fixed: "2.44-r8"}))
	require.NoError(t, err)
	status := http.StatusOK
	f.chainguard.httpClient.Transport = chainguardTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != chainguardAdvisoryURL(testCGA) {
			return nil, errors.New("unexpected advisory URL")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	q.EXPECT().TryAdvisoryLock(mock.Anything, OsvSyncLockKey).Return(true, nil).Twice()
	q.EXPECT().AdvisoryUnlock(mock.Anything, OsvSyncLockKey).Return(true, nil).Twice()
	q.EXPECT().GetVulnerabilitiesForChainguardCorrection(ctx).Return([]*sql.GetVulnerabilitiesForChainguardCorrectionRow{
		{CveID: testCGA, Package: testPurl},
	}, nil).Twice()
	expected := sql.SaveChainguardCorrectionParams{
		CveID: testCGA, Package: testPurl, FixStatus: sql.FixStatusInstalledVersionFixed,
		SourceUrl: chainguardAdvisoryURL(testCGA),
	}
	q.EXPECT().SaveChainguardCorrection(ctx, expected).Return(nil).Once()
	q.EXPECT().ListImagesWithChainguardCorrections(ctx).Return([]*sql.ListImagesWithChainguardCorrectionsRow{
		{ImageName: "image", ImageTag: "v1"},
	}, nil).Twice()
	q.EXPECT().RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "image", ImageTag: "v1",
	}).Return(nil).Twice()
	q.EXPECT().RefreshCveWorkloadCounts(ctx).Return(nil).Twice()
	require.NoError(t, f.Sync(ctx))

	status = http.StatusServiceUnavailable
	expected.FixStatus = sql.FixStatusUnknown
	q.EXPECT().SaveChainguardCorrection(ctx, expected).Return(nil).Once()
	require.NoError(t, f.Sync(ctx))
}

func TestChainguardDisabledClearsCorrections(t *testing.T) {
	ctx := context.Background()
	q := Querier.NewMockQuerier(t)
	log, _ := logrustest.NewNullLogger()
	f := NewFetcherWithQuerier(NewClientWithURL(""), q, log.WithField("test", true)).WithChainguard(false)
	q.EXPECT().TryAdvisoryLock(mock.Anything, OsvSyncLockKey).Return(true, nil).Once()
	q.EXPECT().AdvisoryUnlock(mock.Anything, OsvSyncLockKey).Return(true, nil).Once()
	q.EXPECT().ClearChainguardCorrections(ctx).Return(nil).Once()
	q.EXPECT().ListImagesWithChainguardCorrections(ctx).Return([]*sql.ListImagesWithChainguardCorrectionsRow{
		{ImageName: "image", ImageTag: "v1"},
	}, nil).Once()
	q.EXPECT().RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "image", ImageTag: "v1",
	}).Return(nil).Once()
	q.EXPECT().RefreshCveWorkloadCounts(ctx).Return(nil).Once()
	require.NoError(t, f.Sync(ctx))
}
