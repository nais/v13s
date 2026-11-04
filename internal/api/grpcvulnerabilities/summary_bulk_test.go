package grpcvulnerabilities

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	sqlmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetVulnerabilitySummaries(t *testing.T) {
	ctx := context.Background()
	namespaces := []string{"team-a", "team-b"}

	t.Run("returns each requested team", func(t *testing.T) {
		querier := sqlmock.NewMockQuerier(t)
		querier.EXPECT().GetVulnerabilitySummaries(ctx, sql.GetVulnerabilitySummariesParams{
			Namespaces:    namespaces,
			WorkloadTypes: []string{"app", "job"},
		}).Return([]*sql.GetVulnerabilitySummariesRow{
			{
				Namespace: "team-a", WorkloadCount: 2, WorkloadWithSbom: 2, HighRisk: 3, RiskScore: 4,
				UpdatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
			},
			{Namespace: "team-b"},
		}, nil).Once()

		server := &Server{querier: querier}
		resp, err := server.GetVulnerabilitySummaries(ctx, &vulnerabilities.GetVulnerabilitySummariesRequest{Namespaces: namespaces})
		require.NoError(t, err)
		require.Len(t, resp.GetSummaries(), 2)
		assert.Equal(t, int32(3), resp.Summaries["team-a"].GetVulnerabilitySummary().GetHighRisk())
		assert.Equal(t, int32(2), resp.Summaries["team-a"].GetWorkloadCount())
		assert.Zero(t, resp.Summaries["team-b"].GetWorkloadCount())
		assert.Zero(t, resp.Summaries["team-b"].GetVulnerabilitySummary().GetHighRisk())
		assert.Equal(t, "team-b", resp.Summaries["team-b"].GetFilter().GetNamespace())
	})

	t.Run("missing summary is not a confirmed zero score", func(t *testing.T) {
		for _, hasSummary := range []bool{false, true} {
			t.Run(map[bool]string{false: "missing", true: "confirmed zero"}[hasSummary], func(t *testing.T) {
				querier := sqlmock.NewMockQuerier(t)
				row := &sql.GetVulnerabilitySummariesRow{Namespace: "team-a", WorkloadCount: 1}
				if hasSummary {
					row.WorkloadWithSbom = 1
					row.UpdatedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
				}
				querier.EXPECT().GetVulnerabilitySummaries(ctx, sql.GetVulnerabilitySummariesParams{
					Namespaces: []string{"team-a"}, WorkloadTypes: []string{"app", "job"},
				}).Return([]*sql.GetVulnerabilitySummariesRow{row}, nil).Once()
				response, err := (&Server{querier: querier}).GetVulnerabilitySummaries(ctx,
					&vulnerabilities.GetVulnerabilitySummariesRequest{Namespaces: []string{"team-a"}})
				require.NoError(t, err)
				summary := response.GetSummaries()["team-a"]
				assert.Equal(t, int32(1), summary.GetWorkloadCount())
				if hasSummary {
					require.NotNil(t, summary.GetVulnerabilitySummary())
					assert.True(t, summary.GetVulnerabilitySummary().GetHasSbom())
					assert.NotNil(t, summary.GetVulnerabilitySummary().GetLastUpdated())
					assert.Zero(t, summary.GetVulnerabilitySummary().GetRiskScore())
					assert.Equal(t, int32(1), summary.GetSbomCount())
				} else {
					require.NotNil(t, summary.GetVulnerabilitySummary())
					assert.False(t, summary.GetVulnerabilitySummary().GetHasSbom())
					assert.Nil(t, summary.GetVulnerabilitySummary().GetLastUpdated())
					assert.Zero(t, summary.GetSbomCount())
					assert.Zero(t, summary.GetCoverage())
				}
			})
		}
	})

	t.Run("does not turn missing results into zero summaries", func(t *testing.T) {
		querier := sqlmock.NewMockQuerier(t)
		querier.EXPECT().GetVulnerabilitySummaries(ctx, sql.GetVulnerabilitySummariesParams{
			Namespaces:    namespaces,
			WorkloadTypes: []string{"app", "job"},
		}).Return([]*sql.GetVulnerabilitySummariesRow{{Namespace: "team-a"}}, nil).Once()
		resp, err := (&Server{querier: querier}).GetVulnerabilitySummaries(ctx, &vulnerabilities.GetVulnerabilitySummariesRequest{Namespaces: namespaces})
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("propagates database failures", func(t *testing.T) {
		querier := sqlmock.NewMockQuerier(t)
		querier.EXPECT().GetVulnerabilitySummaries(ctx, sql.GetVulnerabilitySummariesParams{
			Namespaces:    namespaces,
			WorkloadTypes: []string{"app", "job"},
		}).Return(nil, errors.New("database unavailable")).Once()
		resp, err := (&Server{querier: querier}).GetVulnerabilitySummaries(ctx, &vulnerabilities.GetVulnerabilitySummariesRequest{Namespaces: namespaces})
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
	})

	t.Run("rejects invalid selections before querying", func(t *testing.T) {
		server := &Server{}
		for _, request := range []*vulnerabilities.GetVulnerabilitySummariesRequest{
			nil,
			{Namespaces: []string{"team-a", "team-a"}},
			{Namespaces: []string{""}},
			{Namespaces: []string{" team-a"}},
			{Namespaces: make([]string, maxSummaryNamespaces+1)},
			{Namespaces: namespaces, Filter: &vulnerabilities.Filter{Namespace: &namespaces[0]}},
		} {
			resp, err := server.GetVulnerabilitySummaries(ctx, request)
			assert.Nil(t, resp)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		}
	})
}

func TestImageSummaryMissingWhileProcessing(t *testing.T) {
	ctx := context.Background()
	querier := sqlmock.NewMockQuerier(t)
	querier.EXPECT().GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
		ImageName: "registry.example/amt/amt-pdfgen", ImageTag: "dev",
	}).Return(nil, pgx.ErrNoRows).Once()
	querier.EXPECT().ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: "registry.example/amt/amt-pdfgen", ImageTag: "dev",
	}).Return([]*sql.ListWorkloadsByImageRow{{
		Name: "amt-pdfgen", Namespace: "amt", Cluster: "dev", WorkloadType: "app",
		ImageName: "registry.example/amt/amt-pdfgen", ImageTag: "dev",
		State: sql.WorkloadStateProcessing, ImageState: new(sql.ImageStateInitialized),
	}}, nil).Once()

	response, err := (&Server{querier: querier}).GetVulnerabilitySummaryForImage(ctx,
		&vulnerabilities.GetVulnerabilitySummaryForImageRequest{
			ImageName: "registry.example/amt/amt-pdfgen", ImageTag: "dev",
		})
	require.NoError(t, err)
	assert.Nil(t, response.GetVulnerabilitySummary())
	assert.Equal(t, vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, response.GetSbomStatus().GetStatus())
	require.Len(t, response.GetWorkloadRef(), 1)
	assert.Equal(t, "dev", response.GetWorkloadRef()[0].GetCluster())
	assert.Equal(t, "dev", response.GetWorkloadRef()[0].GetImageTag())
}
