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

	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}

	params := sql.ListMeanTimeToFixTrendBySeverityParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
		Since:         timestamptzFromProto(request.GetSince()),
	}

	if request.SinceType != nil {
		sinceType := strings.ToLower(request.GetSinceType().String())
		params.SinceType = &sinceType
	}

	metrics, err := s.querier.ListMeanTimeToFixTrendBySeverity(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list mean time to fix per severity: %w", err)
	}

	ms := collections.Map(metrics, func(row *sql.ListMeanTimeToFixTrendBySeverityRow) *vulnerabilities.MeanTimeToFixTrendPoint {
		return &vulnerabilities.MeanTimeToFixTrendPoint{
			Severity:          vulnerabilities.Severity(row.Severity),
			MeanTimeToFixDays: row.MeanTimeToFixDays,
			SnapshotTime:      timestamppb.New(row.SnapshotTime.Time),
			FixedCount:        row.FixedCount,
			FirstFixedAt:      timestamppb.New(row.FirstFixedAt.Time),
			LastFixedAt:       timestamppb.New(row.LastFixedAt.Time),
		}
	})

	return &vulnerabilities.ListMeanTimeToFixTrendBySeverityResponse{
		Filter: request.GetFilter(),
		Nodes:  ms,
	}, nil
}

func (s *Server) ListWorkloadMTTFBySeverity(ctx context.Context, request *vulnerabilities.ListWorkloadMTTFBySeverityRequest) (*vulnerabilities.ListWorkloadMTTFBySeverityResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}

	params := sql.ListWorkloadSeverityFixStatsParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
		Since:         timestamptzFromProto(request.GetSince()),
	}

	if request.SinceType != nil {
		sinceType := strings.ToLower(request.GetSinceType().String())
		params.SinceType = &sinceType
	}

	rows, err := s.querier.ListWorkloadSeverityFixStats(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list workload severities with mean time to fix: %w", err)
	}

	workloadMap := make(map[string][]*sql.ListWorkloadSeverityFixStatsRow)
	for _, row := range rows {
		wid := row.WorkloadID.String()
		workloadMap[wid] = append(workloadMap[wid], row)
	}

	grouped := make([][]*sql.ListWorkloadSeverityFixStatsRow, 0, len(workloadMap))
	for _, rows := range workloadMap {
		grouped = append(grouped, rows)
	}

	wf := collections.Map(grouped, func(rows []*sql.ListWorkloadSeverityFixStatsRow) *vulnerabilities.WorkloadWithFixes {
		first := rows[0]
		fixes := collections.Map(rows, func(row *sql.ListWorkloadSeverityFixStatsRow) *vulnerabilities.WorkloadFix {
			return &vulnerabilities.WorkloadFix{
				Severity:          vulnerabilities.Severity(row.Severity),
				IntroducedAt:      timestamppb.New(row.IntroducedDate.Time),
				FixedAt:           timestamppb.New(row.FixedAt.Time),
				FixedCount:        row.FixedCount,
				MeanTimeToFixDays: row.MeanTimeToFixDays,
				SnapshotTime:      timestamppb.New(row.SnapshotTime.Time),
			}
		})

		return &vulnerabilities.WorkloadWithFixes{
			WorkloadId:        first.WorkloadID.String(),
			WorkloadNamespace: first.WorkloadNamespace,
			WorkloadName:      first.WorkloadName,
			Fixes:             fixes,
		}
	})

	return &vulnerabilities.ListWorkloadMTTFBySeverityResponse{
		Filter:    request.GetFilter(),
		Workloads: wf,
	}, nil
}
