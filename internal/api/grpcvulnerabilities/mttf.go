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

func (s *Server) ListMeanTimeToFixPerSeverity(ctx context.Context, request *vulnerabilities.ListMeanTimeToFixPerSeverityRequest) (*vulnerabilities.ListMeanTimeToFixPerSeverityResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}

	metrics, err := s.querier.ListMeanTimeToFixPerSeverity(ctx, sql.ListMeanTimeToFixPerSeverityParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list mean time to fix per severity: %w", err)
	}

	ms := collections.Map(metrics, func(row *sql.ListMeanTimeToFixPerSeverityRow) *vulnerabilities.MeanTimeToFixPerSeverity {
		return &vulnerabilities.MeanTimeToFixPerSeverity{
			Severity:          vulnerabilities.Severity(vulnerabilities.Severity_value[strings.ToUpper(row.Severity)]),
			MeanTimeToFixDays: int32(row.MeanTimeToFixDays),
			SnapshotTime:      timestamppb.New(row.SnapshotDate.Time),
			FixedCount:        row.FixedCount,
		}
	})

	return &vulnerabilities.ListMeanTimeToFixPerSeverityResponse{
		Filter: request.GetFilter(),
		Nodes:  ms,
	}, nil
}

func (s *Server) ListWorkloadSeveritiesWithMeanTimeToFix(ctx context.Context, request *vulnerabilities.ListWorkloadSeveritiesWithMeanTimeToFixRequest) (*vulnerabilities.ListWorkloadSeveritiesWithMeanTimeToFixResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}

	severities, err := s.querier.ListWorkloadSeveritiesWithMeanTimeToFix(ctx, sql.ListWorkloadSeveritiesWithMeanTimeToFixParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workload severities with mean time to fix: %w", err)
	}

	wf := collections.Map(severities, func(row *sql.ListWorkloadSeveritiesWithMeanTimeToFixRow) *vulnerabilities.WorkloadFix {
		return &vulnerabilities.WorkloadFix{
			WorkloadId:        row.WorkloadID.String(),
			WorkloadCluster:   row.Cluster,
			WorkloadName:      row.WorkloadName,
			WorkloadNamespace: row.Namespace,
			Severity:          vulnerabilities.Severity(vulnerabilities.Severity_value[strings.ToUpper(row.Severity)]),
			IntroducedAt:      timestamppb.New(row.FirstIntroducedDate.Time),
			FixedAt:           timestamppb.New(row.LastFixedDate.Time),
			FixedCount:        row.FixedCount,
			MeanTimeToFixDays: row.MeanTimeToFixDaysForSeverity,
		}
	})

	return &vulnerabilities.ListWorkloadSeveritiesWithMeanTimeToFixResponse{
		Filter: request.GetFilter(),
		Nodes:  wf,
	}, nil
}
