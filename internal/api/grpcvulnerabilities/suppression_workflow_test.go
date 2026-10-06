package grpcvulnerabilities

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSuppressionWorkflowSuppressOne(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	now := time.Date(2026, 8, 21, 11, 0, 0, 0, time.UTC)
	id := pgtype.UUID{Bytes: uuid.MustParse("00000000-0000-0000-0000-000000000001"), Valid: true}

	q.EXPECT().GetVulnerabilityById(ctx, id).Return(&sql.GetVulnerabilityByIdRow{
		ID:        id,
		ImageName: "img",
		ImageTag:  "v1",
		Package:   "pkg",
		CveID:     "CVE-2025-9999",
	}, nil)
	q.EXPECT().GetAliasesByCanonicalCveId(ctx, "CVE-2025-9999").Return([]string{"GHSA-xxxx-yyyy-zzzz"}, nil)
	q.EXPECT().SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
		ImageName:    "img",
		Package:      "pkg",
		CveID:        "CVE-2025-9999",
		SuppressedBy: "test-user",
		Suppressed:   true,
		Reason:       sql.VulnerabilitySuppressReasonFalsePositive,
		ReasonText:   "accepted risk",
	}).Return(nil)
	q.EXPECT().SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
		ImageName:    "img",
		Package:      "pkg",
		CveID:        "GHSA-xxxx-yyyy-zzzz",
		SuppressedBy: "test-user",
		Suppressed:   true,
		Reason:       sql.VulnerabilitySuppressReasonFalsePositive,
		ReasonText:   "accepted risk",
	}).Return(nil)
	q.EXPECT().RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: "img",
		ImageTag:  "v1",
	}).Return(nil)
	q.EXPECT().UpdateImageState(ctx, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.State == sql.ImageStateResync && p.Name == "img" && p.Tag == "v1" && p.ReadyForResyncAt.Valid && p.ReadyForResyncAt.Time.Equal(now)
	})).Return(int64(1), nil)

	wf := newSuppressionWorkflow(q, func(context.Context, []string) ([]string, error) {
		return []string{"CVE-2025-9999"}, nil
	})
	wf.now = func() time.Time { return now }

	result, err := wf.SuppressOne(ctx, suppressOneInput{
		id:           id,
		suppressedBy: "test-user",
		suppress:     true,
		reason:       sql.VulnerabilitySuppressReasonFalsePositive,
		reasonText:   "accepted risk",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "CVE-2025-9999", result.cveID)
	assert.True(t, result.suppressed)
}

func TestSuppressionWorkflowSuppressOneNotFound(t *testing.T) {
	ctx := context.Background()
	q := mockquerier.NewMockQuerier(t)
	id := pgtype.UUID{Bytes: uuid.MustParse("00000000-0000-0000-0000-000000000099"), Valid: true}

	q.EXPECT().GetVulnerabilityById(ctx, id).Return(nil, pgx.ErrNoRows)

	wf := newSuppressionWorkflow(q, func(context.Context, []string) ([]string, error) {
		return []string{"CVE-2025-9999"}, nil
	})

	result, err := wf.SuppressOne(ctx, suppressOneInput{id: id})
	require.Nil(t, result)
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
