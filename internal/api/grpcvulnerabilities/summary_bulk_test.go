package grpcvulnerabilities

import (
	"context"
	"errors"
	"testing"

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

	t.Run("returns each requested team including confirmed zeros", func(t *testing.T) {
		querier := sqlmock.NewMockQuerier(t)
		querier.EXPECT().GetVulnerabilitySummaries(ctx, sql.GetVulnerabilitySummariesParams{
			Namespaces:    namespaces,
			WorkloadTypes: []string{"app", "job"},
		}).Return([]*sql.GetVulnerabilitySummariesRow{
			{Namespace: "team-a", WorkloadCount: 2, HighRisk: 3, RiskScore: 4},
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
