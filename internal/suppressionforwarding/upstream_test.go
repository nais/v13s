package suppressionforwarding_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/nais/v13s/internal/suppressionforwarding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAdvisories struct {
	records map[string]*osv.VulnRecord
	err     error
	calls   int
}

func (f *fakeAdvisories) FetchVuln(_ context.Context, id string) (*osv.VulnRecord, error) {
	f.calls++
	return f.records[id], f.err
}

func advisory(id string, upstream []string, purls ...string) *osv.VulnRecord {
	r := &osv.VulnRecord{ID: id, Upstream: upstream}
	for _, p := range purls {
		r.Affected = append(r.Affected, osv.Affected{Package: osv.AffectedPackage{Purl: p}})
	}
	return r
}

const glibc = "pkg:apk/chainguard/glibc-2.44"

type upstreamCase struct {
	name   string
	record *osv.VulnRecord
	want   []string
}

func TestUpstreamIDs(t *testing.T) {
	withdrawn := advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, glibc+"?arch=x86_64")
	withdrawn.Withdrawn = "2026-01-01T00:00:00Z"
	for _, tt := range []upstreamCase{
		{name: "package match", record: advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1", "GHSA-1"}, glibc+"?arch=x86_64", "pkg:apk/wolfi/glibc-2.44"), want: []string{"CVE-1", "GHSA-1"}},
		{name: "other package", record: advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, "pkg:apk/chainguard/zlib")},
		{name: "withdrawn", record: withdrawn},
		{name: "two CVEs", record: advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1", "CVE-2"}, glibc)},
		{name: "no upstream", record: advisory("CGA-aaaa-bbbb-cccc", nil, glibc)},
		{name: "unknown advisory"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := suppressionforwarding.NewUpstream(&fakeAdvisories{records: map[string]*osv.VulnRecord{"CGA-aaaa-bbbb-cccc": tt.record}})
			got, err := u.IDs(context.Background(), []string{"CGA-aaaa-bbbb-cccc"}, glibc)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUpstreamSkipsOtherIDsAndCaches(t *testing.T) {
	fetcher := &fakeAdvisories{records: map[string]*osv.VulnRecord{"CGA-aaaa-bbbb-cccc": advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, glibc)}}
	u := suppressionforwarding.NewUpstream(fetcher)
	for range 3 {
		got, err := u.IDs(context.Background(), []string{"CVE-1", "GHSA-1", "CGA-aaaa-bbbb-cccc"}, glibc)
		require.NoError(t, err)
		assert.Empty(t, got, "upstream IDs already in the group are not repeated")
	}
	assert.Equal(t, 1, fetcher.calls)
}

func TestForwardAddsUpstreamIDs(t *testing.T) {
	v0s := &fakeV0s{response: applied(1)}
	log, hook := newLogger()
	fetcher := &fakeAdvisories{records: map[string]*osv.VulnRecord{"CGA-aaaa-bbbb-cccc": advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1", "GHSA-1"}, glibc+"?arch=aarch64")}}
	f := suppressionforwarding.New(v0s, time.Second, suppressionforwarding.NewUpstream(fetcher), log)
	cga := suppressionforwarding.Change{ImageName: "ghcr.io/navikt/app", Package: glibc + "@2.44-r1?arch=aarch64", VulnerabilityIDs: []string{"CGA-aaaa-bbbb-cccc"}}

	f.Forward(context.Background(), fakeSource{rows: []*sql.SuppressedVulnerability{
		row(glibc+"@2.44-r1?arch=aarch64", "CGA-aaaa-bbbb-cccc", true, sql.VulnerabilitySuppressReasonNotAffected, earlier),
	}}, cga)
	require.Len(t, v0s.requests, 1)
	assert.Equal(t, []string{"CGA-aaaa-bbbb-cccc", "CVE-1", "GHSA-1"}, v0s.requests[0].GetVulnerabilityIds())
	assert.Equal(t, suppressionforwarding.OutcomeApplied, lastEntry(t, hook).Data["outcome"])

	fetcher.err, fetcher.records = errors.New("osv down"), nil
	f = suppressionforwarding.New(v0s, time.Second, suppressionforwarding.NewUpstream(fetcher), log)
	f.Forward(context.Background(), fakeSource{rows: []*sql.SuppressedVulnerability{
		row(glibc+"@2.44-r1?arch=aarch64", "CGA-aaaa-bbbb-cccc", true, sql.VulnerabilitySuppressReasonNotAffected, earlier),
	}}, cga)
	assert.Len(t, v0s.requests, 1)
	assert.Equal(t, suppressionforwarding.OutcomeAdvisoryLookupFailed, lastEntry(t, hook).Data["outcome"])
}

func TestUpstreamDropsIDsThatCollideAcrossTheGroup(t *testing.T) {
	fetcher := &fakeAdvisories{records: map[string]*osv.VulnRecord{
		"CGA-aaaa-bbbb-cccc": advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, glibc),
		"CGA-dddd-eeee-ffff": advisory("CGA-dddd-eeee-ffff", []string{"CVE-2"}, glibc),
	}}
	u := suppressionforwarding.NewUpstream(fetcher)

	got, err := u.IDs(context.Background(), []string{"CGA-aaaa-bbbb-cccc", "CGA-dddd-eeee-ffff"}, glibc)
	require.NoError(t, err)
	assert.Empty(t, got, "two advisories naming different CVEs")

	got, err = u.IDs(context.Background(), []string{"CVE-9", "CGA-aaaa-bbbb-cccc"}, glibc)
	require.NoError(t, err)
	assert.Empty(t, got, "the group already names another CVE")
}

func TestUpstreamRefetchesAfterTTL(t *testing.T) {
	record := advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, glibc)
	fetcher := &fakeAdvisories{records: map[string]*osv.VulnRecord{"CGA-aaaa-bbbb-cccc": record}}
	u := suppressionforwarding.NewUpstream(fetcher)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	suppressionforwarding.SetUpstreamClock(u, func() time.Time { return now })

	got, err := u.IDs(context.Background(), []string{"CGA-aaaa-bbbb-cccc"}, glibc)
	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-1"}, got)

	withdrawn := *record
	withdrawn.Withdrawn = "2026-01-01T00:30:00Z"
	fetcher.records["CGA-aaaa-bbbb-cccc"] = &withdrawn
	now = now.Add(30 * time.Minute)
	got, _ = u.IDs(context.Background(), []string{"CGA-aaaa-bbbb-cccc"}, glibc)
	assert.Equal(t, []string{"CVE-1"}, got, "still cached")

	now = now.Add(time.Hour)
	got, _ = u.IDs(context.Background(), []string{"CGA-aaaa-bbbb-cccc"}, glibc)
	assert.Empty(t, got, "withdrawal seen after the cache expires")
	assert.Equal(t, 2, fetcher.calls)
}

func TestForwardChecksChainguardAndUpstreamRowsTogether(t *testing.T) {
	fetcher := &fakeAdvisories{records: map[string]*osv.VulnRecord{"CGA-aaaa-bbbb-cccc": advisory("CGA-aaaa-bbbb-cccc", []string{"CVE-1"}, glibc)}}
	log, hook := newLogger()
	v0s := &fakeV0s{response: applied(1)}
	f := suppressionforwarding.New(v0s, time.Second, suppressionforwarding.NewUpstream(fetcher), log)
	conflicting := fakeSource{rows: []*sql.SuppressedVulnerability{
		row(glibc+"@2.44-r1", "CGA-aaaa-bbbb-cccc", false, sql.VulnerabilitySuppressReasonNotSet, later),
		row(glibc+"@2.43-r0", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier),
	}}

	f.Forward(context.Background(), conflicting, suppressionforwarding.Change{ImageName: "ghcr.io/navikt/app", Package: glibc + "@2.44-r1", VulnerabilityIDs: []string{"CGA-aaaa-bbbb-cccc"}})
	assert.Equal(t, suppressionforwarding.OutcomeConflictingAssessments, lastEntry(t, hook).Data["outcome"], "a removal through the advisory")
	f.Forward(context.Background(), conflicting, suppressionforwarding.Change{ImageName: "ghcr.io/navikt/app", Package: glibc + "@2.43-r0", VulnerabilityIDs: []string{"CVE-1"}})
	assert.Equal(t, suppressionforwarding.OutcomeConflictingAssessments, lastEntry(t, hook).Data["outcome"], "a change through the upstream ID")
	assert.Empty(t, v0s.requests)

	agreeing := fakeSource{rows: []*sql.SuppressedVulnerability{
		row(glibc+"@2.44-r1", "CGA-aaaa-bbbb-cccc", true, sql.VulnerabilitySuppressReasonNotAffected, later),
		row(glibc+"@2.43-r0", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier),
	}}
	f.Forward(context.Background(), agreeing, suppressionforwarding.Change{ImageName: "ghcr.io/navikt/app", Package: glibc + "@2.43-r0", VulnerabilityIDs: []string{"CVE-1"}})
	require.Len(t, v0s.requests, 1)
	assert.Equal(t, []string{"CVE-1", "CGA-aaaa-bbbb-cccc"}, v0s.requests[0].GetVulnerabilityIds())
	assert.True(t, v0s.requests[0].GetAssessment().GetUpdatedAt().AsTime().Equal(later))
}
