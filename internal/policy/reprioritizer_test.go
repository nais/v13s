package policy_test

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/policy"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

//go:fix inline
func ptr[T any](v T) *T { return new(v) }

func TestReprioritizer_ReprioritizeAll_OnlyWritesChangedRows(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetCvesForPriorityRecompute(mock.Anything).Return([]*sql.GetCvesForPriorityRecomputeRow{
		{CveID: "CVE-KEV", HasKevEntry: true, Priority: ptr(policy.PriorityMonitor)},
		{CveID: "CVE-ALREADY-HIGH", HasKevEntry: true, Priority: ptr(policy.PriorityHigh)},
		{CveID: "CVE-QUIET", Priority: ptr(policy.PriorityMonitor)},
	}, nil)
	q.EXPECT().BulkUpdateCvePriorities(mock.Anything, sql.BulkUpdateCvePrioritiesParams{
		CveIds:     []string{"CVE-KEV"},
		Priorities: []int32{policy.PriorityHigh},
	}).Return(int64(1), nil)

	eval, err := policy.NewPriorityEvaluator()
	require.NoError(t, err)
	r := policy.NewReprioritizer(q, eval)

	updated, err := r.ReprioritizeAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), updated)
}

func TestReprioritizer_ReprioritizeAll_NoChangesSkipsWrite(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetCvesForPriorityRecompute(mock.Anything).Return([]*sql.GetCvesForPriorityRecomputeRow{
		{CveID: "CVE-QUIET", Priority: ptr(policy.PriorityMonitor)},
	}, nil)
	// No BulkUpdateCvePriorities expectation: it must not be called.

	eval, err := policy.NewPriorityEvaluator()
	require.NoError(t, err)
	r := policy.NewReprioritizer(q, eval)

	updated, err := r.ReprioritizeAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(0), updated)
}

func TestReprioritizer_ReprioritizeCves_EmptyInputSkipsQuery(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	// No GetCvesForPriorityRecomputeByIDs expectation: it must not be called.

	eval, err := policy.NewPriorityEvaluator()
	require.NoError(t, err)
	r := policy.NewReprioritizer(q, eval)

	updated, err := r.ReprioritizeCves(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int64(0), updated)
}

func TestReprioritizer_ReprioritizeCves_ScopesToGivenIDs(t *testing.T) {
	q := mockquerier.NewMockQuerier(t)
	q.EXPECT().GetCvesForPriorityRecomputeByIDs(mock.Anything, []string{"CVE-A"}).Return([]*sql.GetCvesForPriorityRecomputeByIDsRow{
		{CveID: "CVE-A", KnownRansomwareUse: true, Priority: ptr(policy.PriorityMonitor)},
	}, nil)
	q.EXPECT().BulkUpdateCvePriorities(mock.Anything, sql.BulkUpdateCvePrioritiesParams{
		CveIds:     []string{"CVE-A"},
		Priorities: []int32{policy.PriorityHigh},
	}).Return(int64(1), nil)

	eval, err := policy.NewPriorityEvaluator()
	require.NoError(t, err)
	r := policy.NewReprioritizer(q, eval)

	updated, err := r.ReprioritizeCves(context.Background(), []string{"CVE-A"})
	require.NoError(t, err)
	require.Equal(t, int64(1), updated)
}
