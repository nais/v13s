package suppressionforwarding_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/suppressionforwarding"
	"github.com/nais/v13s/internal/suppressionforwarding/v0sapi"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	actor  = "secret-actor@example.com"
	reason = "secret reason text"
)

var (
	earlier = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	later   = earlier.Add(time.Hour)
)

type fakeV0s struct {
	requests []*v0sapi.ForwardV13SSuppressionRequest
	response *v0sapi.ForwardV13SSuppressionResponse
	err      error
	block    bool
}

func (f *fakeV0s) Invoke(ctx context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	if method != v0sapi.SuppressionService_ForwardV13SSuppression_FullMethodName {
		return status.Errorf(codes.Unimplemented, "unexpected method %s", method)
	}
	f.requests = append(f.requests, proto.Clone(args.(*v0sapi.ForwardV13SSuppressionRequest)).(*v0sapi.ForwardV13SSuppressionRequest))
	if f.block {
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	}
	if f.err != nil {
		return f.err
	}
	proto.Merge(reply.(proto.Message), f.response)
	return nil
}

func (f *fakeV0s) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not supported")
}

type fakeSource struct {
	rows []*sql.SuppressedVulnerability
	err  error
}

func (f fakeSource) ListSuppressedVulnerabilitiesForImage(context.Context, string) ([]*sql.SuppressedVulnerability, error) {
	return f.rows, f.err
}

func row(pkg, cveID string, suppressed bool, r sql.VulnerabilitySuppressReason, updatedAt time.Time) *sql.SuppressedVulnerability {
	return &sql.SuppressedVulnerability{
		ImageName:    "ghcr.io/navikt/app",
		Package:      pkg,
		CveID:        cveID,
		Suppressed:   suppressed,
		Reason:       r,
		ReasonText:   reason,
		SuppressedBy: actor,
		UpdatedAt:    pgtype.Timestamptz{Time: updatedAt, Valid: true},
	}
}

var change = suppressionforwarding.Change{
	ImageName:        "ghcr.io/navikt/app",
	Package:          "pkg:npm/lodash@4.17.20?arch=x",
	VulnerabilityIDs: []string{"CVE-1", "GHSA-1"},
}

func applied(n int32) *v0sapi.ForwardV13SSuppressionResponse {
	return &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_APPLIED, Applied: n}
}

func newLogger() (*logrus.Logger, *logtest.Hook) {
	return logtest.NewNullLogger()
}

func newForwarder(v0s *fakeV0s, timeout time.Duration) (*suppressionforwarding.Forwarder, *logtest.Hook) {
	log, hook := newLogger()
	return suppressionforwarding.New(v0s, timeout, nil, log), hook
}

func forwardCount(outcome suppressionforwarding.Outcome) float64 {
	return testutil.ToFloat64(metrics.SuppressionForwards.WithLabelValues(string(outcome)))
}

func lastEntry(t *testing.T, hook *logtest.Hook) *logrus.Entry {
	t.Helper()
	entry := hook.LastEntry()
	require.NotNil(t, entry)
	for key, value := range entry.Data {
		text := fmt.Sprint(value)
		assert.NotContains(t, text, actor, "log field %s", key)
		assert.NotContains(t, text, reason, "log field %s", key)
	}
	assert.False(t, strings.Contains(entry.Message, actor) || strings.Contains(entry.Message, reason))
	return entry
}

func TestForwardSendsAgreedGroup(t *testing.T) {
	v0s := &fakeV0s{response: applied(3)}
	f, hook := newForwarder(v0s, time.Second)
	before := forwardCount(suppressionforwarding.OutcomeApplied)

	f.Forward(context.Background(), fakeSource{rows: []*sql.SuppressedVulnerability{
		row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonInTriage, earlier),
		row("pkg:npm/lodash@4.17.20", "GHSA-1", true, sql.VulnerabilitySuppressReasonInTriage, later),
		row("pkg:npm/lodash@4.17.19?arch=y", "CVE-1", true, sql.VulnerabilitySuppressReasonResolved, earlier),
		row("pkg:npm/lodash@4.17.20", "CVE-2", false, sql.VulnerabilitySuppressReasonNotSet, later),
		row("pkg:npm/express@4.0.0", "CVE-1", false, sql.VulnerabilitySuppressReasonNotSet, later),
		row("not a purl", "CVE-1", false, sql.VulnerabilitySuppressReasonNotSet, later),
	}}, change)

	require.Len(t, v0s.requests, 1)
	req := v0s.requests[0]
	assert.Equal(t, "ghcr.io/navikt/app", req.GetImageName())
	assert.Equal(t, "pkg:npm/lodash", req.GetPackage())
	assert.Equal(t, []string{"CVE-1", "GHSA-1"}, req.GetVulnerabilityIds())
	assert.Equal(t, v0sapi.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, req.GetAssessment().GetState())
	assert.Equal(t, reason, req.GetAssessment().GetDetail())
	assert.Equal(t, actor, req.GetAssessment().GetUpdatedBy())
	assert.True(t, req.GetAssessment().GetUpdatedAt().AsTime().Equal(later))

	assert.Equal(t, before+1, forwardCount(suppressionforwarding.OutcomeApplied))
	entry := lastEntry(t, hook)
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, suppressionforwarding.OutcomeApplied, entry.Data["outcome"])
	assert.Equal(t, "pkg:npm/lodash", entry.Data["package_key"])
	assert.Equal(t, "CVE-1", entry.Data["vulnerability_id"])
	assert.Equal(t, later, entry.Data["source_updated_at"])
	assert.Equal(t, int32(3), entry.Data["applied"])
	assert.Contains(t, entry.Data, "acknowledged_at")
}

func TestForwardUnsuppression(t *testing.T) {
	v0s := &fakeV0s{response: &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_APPLIED, Removed: 2}}
	f, hook := newForwarder(v0s, time.Second)
	unsuppressed := row("pkg:npm/lodash@4.17.20", "CVE-1", false, sql.VulnerabilitySuppressReasonNotSet, later)
	unsuppressed.ReasonText, unsuppressed.SuppressedBy = "", ""

	f.Forward(context.Background(), fakeSource{rows: []*sql.SuppressedVulnerability{
		unsuppressed,
		row("pkg:npm/lodash@4.17.20", "GHSA-1", false, sql.VulnerabilitySuppressReasonFalsePositive, earlier),
	}}, change)

	require.Len(t, v0s.requests, 1)
	assert.Nil(t, v0s.requests[0].GetAssessment())
	assert.Equal(t, int32(2), lastEntry(t, hook).Data["removed"])
}

type blockedGroup struct {
	name string
	rows []*sql.SuppressedVulnerability
	want suppressionforwarding.Outcome
}

func TestForwardBlocksWithoutCallingV0s(t *testing.T) {
	differentActor := row("pkg:npm/lodash@4.17.19", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)
	differentActor.SuppressedBy = "someone-else"
	noReason := row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)
	noReason.ReasonText = ""
	noActor := row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)
	noActor.SuppressedBy = ""
	notAffected := row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)

	for _, tt := range []blockedGroup{
		{name: "enabled flags", rows: []*sql.SuppressedVulnerability{notAffected, row("pkg:npm/lodash@4.17.20", "GHSA-1", false, sql.VulnerabilitySuppressReasonNotAffected, earlier)}, want: suppressionforwarding.OutcomeConflictingAssessments},
		{name: "states", rows: []*sql.SuppressedVulnerability{notAffected, row("pkg:npm/lodash@4.17.19", "CVE-1", true, sql.VulnerabilitySuppressReasonFalsePositive, earlier)}, want: suppressionforwarding.OutcomeConflictingAssessments},
		{name: "actors", rows: []*sql.SuppressedVulnerability{notAffected, differentActor}, want: suppressionforwarding.OutcomeConflictingAssessments},
		{name: "not set", rows: []*sql.SuppressedVulnerability{row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotSet, earlier)}, want: suppressionforwarding.OutcomeUnsupportedReason},
		{name: "no reason text", rows: []*sql.SuppressedVulnerability{noReason}, want: suppressionforwarding.OutcomeIncompleteAssessment},
		{name: "no actor", rows: []*sql.SuppressedVulnerability{noActor}, want: suppressionforwarding.OutcomeIncompleteAssessment},
		{name: "no rows", rows: []*sql.SuppressedVulnerability{row("pkg:npm/express@4.0.0", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)}, want: suppressionforwarding.OutcomeNoSourceRows},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v0s := &fakeV0s{response: applied(1)}
			f, hook := newForwarder(v0s, time.Second)
			before := forwardCount(tt.want)

			f.Forward(context.Background(), fakeSource{rows: tt.rows}, change)

			assert.Empty(t, v0s.requests)
			assert.Equal(t, before+1, forwardCount(tt.want))
			entry := lastEntry(t, hook)
			assert.Equal(t, logrus.WarnLevel, entry.Level)
			assert.Equal(t, tt.want, entry.Data["outcome"])
		})
	}
}

func TestForwardSourceAndPackageFailures(t *testing.T) {
	v0s := &fakeV0s{response: applied(1)}
	f, hook := newForwarder(v0s, time.Second)

	f.Forward(context.Background(), fakeSource{err: errors.New("connection refused to " + reason)}, change)
	assert.Equal(t, suppressionforwarding.OutcomeSourceReadFailed, lastEntry(t, hook).Data["outcome"])

	unparsable := change
	unparsable.Package = "lodash"
	f.Forward(context.Background(), fakeSource{}, unparsable)
	assert.Equal(t, suppressionforwarding.OutcomeUnsupportedPackage, lastEntry(t, hook).Data["outcome"])
	assert.Empty(t, v0s.requests)
}

type v0sOutcome struct {
	name     string
	response *v0sapi.ForwardV13SSuppressionResponse
	err      error
	want     suppressionforwarding.Outcome
	wantCode string
}

func TestForwardReportsV0sOutcomes(t *testing.T) {
	rows := []*sql.SuppressedVulnerability{row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)}
	for _, tt := range []v0sOutcome{
		{name: "no workloads", response: &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_NO_WORKLOADS}, want: suppressionforwarding.OutcomeNoWorkloads},
		{name: "unknown", response: &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_UNKNOWN_VULNERABILITY}, want: suppressionforwarding.OutcomeUnknownVulnerability},
		{name: "ambiguous", response: &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_AMBIGUOUS_VULNERABILITY}, want: suppressionforwarding.OutcomeAmbiguousVulnerability},
		{name: "unspecified", response: &v0sapi.ForwardV13SSuppressionResponse{}, want: suppressionforwarding.OutcomeFailed},
		{name: "unavailable", err: status.Error(codes.Unavailable, "dial tcp: "+reason), want: suppressionforwarding.OutcomeFailed, wantCode: "Unavailable"},
		{name: "disabled receiver", err: status.Error(codes.FailedPrecondition, "not enabled"), want: suppressionforwarding.OutcomeFailed, wantCode: "FailedPrecondition"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, hook := newForwarder(&fakeV0s{response: tt.response, err: tt.err}, time.Second)
			f.Forward(context.Background(), fakeSource{rows: rows}, change)
			entry := lastEntry(t, hook)
			assert.Equal(t, logrus.WarnLevel, entry.Level)
			assert.Equal(t, tt.want, entry.Data["outcome"])
			if tt.wantCode != "" {
				assert.Equal(t, tt.wantCode, entry.Data["grpc_code"])
			}
		})
	}
}

func TestForwardIsBoundedAndOutlivesCancellation(t *testing.T) {
	rows := []*sql.SuppressedVulnerability{row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonNotAffected, earlier)}

	v0s := &fakeV0s{block: true}
	f, hook := newForwarder(v0s, 50*time.Millisecond)
	start := time.Now()
	f.Forward(context.Background(), fakeSource{rows: rows}, change)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, "DeadlineExceeded", lastEntry(t, hook).Data["grpc_code"])

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	v0s = &fakeV0s{response: applied(1)}
	f, hook = newForwarder(v0s, time.Second)
	f.Forward(canceled, fakeSource{rows: rows}, change)
	require.Len(t, v0s.requests, 1)
	assert.Equal(t, suppressionforwarding.OutcomeApplied, lastEntry(t, hook).Data["outcome"])
}

func TestNilForwarderDoesNothing(t *testing.T) {
	var f *suppressionforwarding.Forwarder
	f.Forward(context.Background(), fakeSource{err: errors.New("must not be read")}, change)
}

func TestForwardMergesDifferingReasonTexts(t *testing.T) {
	v0s := &fakeV0s{response: applied(1)}
	f, hook := newForwarder(v0s, time.Second)
	newer := row("pkg:npm/lodash@4.17.21", "GHSA-1", true, sql.VulnerabilitySuppressReasonResolved, later)
	newer.ReasonText = "patched upstream"
	sameAsNewer := row("pkg:npm/lodash@4.17.20", "CVE-1", true, sql.VulnerabilitySuppressReasonInTriage, earlier)
	sameAsNewer.ReasonText = "patched upstream"
	noText := row("pkg:npm/lodash", "CVE-1", true, sql.VulnerabilitySuppressReasonInTriage, earlier)
	noText.ReasonText = ""

	f.Forward(context.Background(), fakeSource{rows: []*sql.SuppressedVulnerability{
		row("pkg:npm/lodash@4.17.19", "CVE-1", true, sql.VulnerabilitySuppressReasonInTriage, earlier),
		newer,
		sameAsNewer,
		noText,
	}}, change)

	require.Len(t, v0s.requests, 1)
	a := v0s.requests[0].GetAssessment()
	assert.Equal(t, v0sapi.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, a.GetState())
	assert.Equal(t, "4.17.20, 4.17.21: patched upstream\n\n4.17.19: "+reason, a.GetDetail())
	assert.Equal(t, actor, a.GetUpdatedBy())
	assert.True(t, a.GetUpdatedAt().AsTime().Equal(later))
	assert.Equal(t, suppressionforwarding.OutcomeApplied, lastEntry(t, hook).Data["outcome"])
}
