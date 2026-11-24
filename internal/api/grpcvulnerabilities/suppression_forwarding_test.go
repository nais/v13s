package grpcvulnerabilities

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	v0sapi "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/suppressionforwarding"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type recordingV0s struct {
	requests []*v0sapi.ForwardV13SSuppressionRequest
	err      error
}

func (r *recordingV0s) Invoke(_ context.Context, _ string, args, reply any, _ ...grpc.CallOption) error {
	r.requests = append(r.requests, proto.Clone(args.(*v0sapi.ForwardV13SSuppressionRequest)).(*v0sapi.ForwardV13SSuppressionRequest))
	if r.err != nil {
		return r.err
	}
	proto.Merge(reply.(proto.Message), &v0sapi.ForwardV13SSuppressionResponse{Outcome: v0sapi.ForwardOutcome_FORWARD_OUTCOME_APPLIED, Applied: 2})
	return nil
}

func (r *recordingV0s) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not supported")
}

type forwardingFixture struct {
	querier *mockquerier.MockQuerier
	v0s     *recordingV0s
	hook    *logtest.Hook
	wf      suppressionWorkflow
	id      pgtype.UUID
}

var persistedAt = time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)

func newForwardingFixture(t *testing.T) forwardingFixture {
	q := mockquerier.NewMockQuerier(t)
	v0s := &recordingV0s{}
	log, hook := logtest.NewNullLogger()
	wf := newSuppressionWorkflow(q, func(context.Context, []string) ([]string, error) {
		return []string{"CVE-2025-9999"}, nil
	})
	wf.now = func() time.Time { return persistedAt }
	wf.forwarder = suppressionforwarding.New(v0s, time.Second, nil, log)
	id := pgtype.UUID{Bytes: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Valid: true}
	q.EXPECT().GetVulnerabilityById(mock.Anything, id).Return(&sql.GetVulnerabilityByIdRow{
		ID: id, ImageName: "img", ImageTag: "v1", Package: "pkg:npm/lodash@4.17.20", CveID: "CVE-2025-9999",
	}, nil)
	q.EXPECT().GetAliasesByCanonicalCveId(mock.Anything, "CVE-2025-9999").Return([]string{"GHSA-xxxx-yyyy-zzzz"}, nil)
	return forwardingFixture{querier: q, v0s: v0s, hook: hook, wf: wf, id: id}
}

func (f forwardingFixture) suppress() (*suppressOneResult, error) {
	return f.wf.SuppressOne(context.Background(), suppressOneInput{
		id: f.id, suppressedBy: "test-user", suppress: true,
		reason: sql.VulnerabilitySuppressReasonNotAffected, reasonText: "not reachable",
	})
}

func (f forwardingFixture) expectWrite(cveID string, err error) {
	f.querier.EXPECT().SuppressVulnerability(mock.Anything, mock.MatchedBy(func(p sql.SuppressVulnerabilityParams) bool {
		return p.CveID == cveID
	})).Return(err).Once()
}

func (f forwardingFixture) expectPersisted(rows ...*sql.SuppressedVulnerability) {
	f.querier.EXPECT().ListSuppressedVulnerabilitiesForImage(mock.Anything, "img").Return(rows, nil).Once()
}

func (f forwardingFixture) expectSummaryAndResync(summaryErr error) {
	f.querier.EXPECT().RecalculateVulnerabilitySummary(mock.Anything, mock.Anything).Return(summaryErr).Once()
	if summaryErr == nil {
		f.querier.EXPECT().UpdateImageState(mock.Anything, mock.Anything).Return(int64(1), nil).Once()
	}
}

func persisted(cveID string) *sql.SuppressedVulnerability {
	return &sql.SuppressedVulnerability{
		ImageName: "img", Package: "pkg:npm/lodash@4.17.20", CveID: cveID, Suppressed: true,
		Reason: sql.VulnerabilitySuppressReasonNotAffected, ReasonText: "not reachable", SuppressedBy: "test-user",
		UpdatedAt: pgtype.Timestamptz{Time: persistedAt, Valid: true},
	}
}

func TestSuppressOneForwardsPersistedGroup(t *testing.T) {
	f := newForwardingFixture(t)
	f.expectWrite("CVE-2025-9999", nil)
	f.expectWrite("GHSA-xxxx-yyyy-zzzz", nil)
	f.expectSummaryAndResync(nil)
	f.expectPersisted(persisted("CVE-2025-9999"), persisted("GHSA-xxxx-yyyy-zzzz"))

	result, err := f.suppress()
	require.NoError(t, err)
	assert.True(t, result.suppressed)
	require.Len(t, f.v0s.requests, 1)
	req := f.v0s.requests[0]
	assert.Equal(t, "pkg:npm/lodash", req.GetPackage())
	assert.Equal(t, []string{"CVE-2025-9999", "GHSA-xxxx-yyyy-zzzz"}, req.GetVulnerabilityIds())
	assert.Equal(t, v0sapi.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED, req.GetAssessment().GetState())
	assert.True(t, req.GetAssessment().GetUpdatedAt().AsTime().Equal(persistedAt))
}

func TestSuppressOneForwardsAfterPartialAliasWrite(t *testing.T) {
	f := newForwardingFixture(t)
	f.expectWrite("CVE-2025-9999", nil)
	f.expectWrite("GHSA-xxxx-yyyy-zzzz", errors.New("write failed"))
	f.expectPersisted(persisted("CVE-2025-9999"))

	_, err := f.suppress()
	require.Error(t, err)
	require.Len(t, f.v0s.requests, 1)
	assert.Equal(t, "not reachable", f.v0s.requests[0].GetAssessment().GetDetail())
}

func TestSuppressOneDoesNotForwardWhenNothingWasWritten(t *testing.T) {
	f := newForwardingFixture(t)
	f.expectWrite("CVE-2025-9999", errors.New("write failed"))
	f.expectWrite("GHSA-xxxx-yyyy-zzzz", errors.New("write failed"))

	_, err := f.suppress()
	require.Error(t, err)
	assert.Empty(t, f.v0s.requests)
}

func TestSuppressOneForwardsAfterSummaryFailure(t *testing.T) {
	f := newForwardingFixture(t)
	f.expectWrite("CVE-2025-9999", nil)
	f.expectWrite("GHSA-xxxx-yyyy-zzzz", nil)
	f.expectSummaryAndResync(errors.New("summary failed"))
	f.expectPersisted(persisted("CVE-2025-9999"), persisted("GHSA-xxxx-yyyy-zzzz"))

	_, err := f.suppress()
	require.Error(t, err)
	assert.Len(t, f.v0s.requests, 1)
}

func TestSuppressOneSucceedsWhenV0sFails(t *testing.T) {
	f := newForwardingFixture(t)
	f.v0s.err = status.Error(codes.Unavailable, "unavailable")
	f.expectWrite("CVE-2025-9999", nil)
	f.expectWrite("GHSA-xxxx-yyyy-zzzz", nil)
	f.expectSummaryAndResync(nil)
	f.expectPersisted(persisted("CVE-2025-9999"), persisted("GHSA-xxxx-yyyy-zzzz"))

	result, err := f.suppress()
	require.NoError(t, err)
	assert.True(t, result.suppressed)
	entry := f.hook.LastEntry()
	require.NotNil(t, entry)
	assert.Equal(t, logrus.WarnLevel, entry.Level)
	assert.Equal(t, "Unavailable", entry.Data["grpc_code"])
}
