package grpcvulnerabilities

import (
	"context"
	"fmt"
	"strings"

	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) ListMeanTimeToFixTrendBySeverity(ctx context.Context, request *vulnerabilities.ListMeanTimeToFixTrendBySeverityRequest) (*vulnerabilities.ListMeanTimeToFixTrendBySeverityResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	params := sql.ListMeanTimeToFixTrendBySeverityParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: request.Filter.GetWorkloadTypes(),
		WorkloadName:  request.GetFilter().Workload,
		Since:         timestamptzFromProto(request.GetSince()),
	}

	if request.SinceType != nil {
		params.SinceType = new(strings.ToLower(request.GetSinceType().String()))
	}

	metrics, err := s.querier.ListMeanTimeToFixTrendBySeverity(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list mean time to fix per severity: %w", err)
	}

	ms := collections.Map(metrics, func(row *sql.ListMeanTimeToFixTrendBySeverityRow) *vulnerabilities.MeanTimeToFixTrendPoint {
		return &vulnerabilities.MeanTimeToFixTrendPoint{
			Severity:          vulnerabilities.Severity(row.Severity),
			MeanTimeToFixDays: row.MeanTimeToFixDays,
			SnapshotDate:      timestamppb.New(row.SnapshotDate.Time),
			FixedCount:        row.FixedCount,
			FirstFixedAt:      timestamppb.New(row.FirstFixedAt.Time),
			LastFixedAt:       timestamppb.New(row.LastFixedAt.Time),
			WorkloadCount:     row.RegisteredWorkloads,
		}
	})

	return &vulnerabilities.ListMeanTimeToFixTrendBySeverityResponse{
		Filter: request.GetFilter(),
		Points: ms,
	}, nil
}
