package grpcvulnerabilities

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) ListWorkloadCriticalVulnerabilitiesSince(ctx context.Context, request *vulnerabilities.ListWorkloadCriticalVulnerabilitiesSinceRequest) (*vulnerabilities.ListWorkloadCriticalVulnerabilitiesSinceResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	since := pgtype.Timestamptz{}
	if request.GetSince() != nil {
		since.Time = request.GetSince().AsTime().UTC()
		since.Valid = true
	}

	result, err := s.querier.ListWorkloadVulnerabilitiesBecameCriticalSince(ctx, sql.ListWorkloadVulnerabilitiesBecameCriticalSinceParams{
		Cluster:           request.GetFilter().Cluster,
		Namespace:         request.GetFilter().Namespace,
		WorkloadType:      request.GetFilter().FuzzyWorkloadType(),
		WorkloadName:      request.GetFilter().Workload,
		IncludeSuppressed: request.IncludeSuppressed,
		IncludeUnresolved: request.IncludeResolved,
		Since:             since,
		Limit:             limit,
		Offset:            offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	vulnz := collections.Map(result, func(row *sql.ListWorkloadVulnerabilitiesBecameCriticalSinceRow) *vulnerabilities.WorkloadCriticalVulnerabilityFinding {

		return &vulnerabilities.WorkloadCriticalVulnerabilityFinding{
			WorkloadRef: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: row.ImageName,
				ImageTag:  row.ImageTag,
			},
			Vulnerability: &vulnerabilities.WorkloadCriticalVulnerability{
				Id:      row.CveID,
				Package: row.Package,
				Suppression: toSuppression(
					row.Suppressed,
					row.Reason.VulnerabilitySuppressReason,
					row.ReasonText,
					row.SuppressedBy,
					row.SuppressedAt.Time,
				),
				CreatedAt:        toProtoTimestamp(row.CreatedAt),
				BecameCriticalAt: toProtoTimestamp(row.BecameCriticalAt),
				ResolvedAt:       toProtoTimestamp(row.ResolvedAt),
				Cve: &vulnerabilities.Cve{
					Id: row.CveID,
				},
			},
		}
	})

	total, err := s.querier.CountWorkloadVulnerabilities(ctx, sql.CountWorkloadVulnerabilitiesParams{
		Cluster:           request.GetFilter().Cluster,
		Namespace:         request.GetFilter().Namespace,
		WorkloadType:      request.GetFilter().FuzzyWorkloadType(),
		WorkloadName:      request.GetFilter().Workload,
		IncludeSuppressed: request.IncludeSuppressed,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListWorkloadCriticalVulnerabilitiesSinceResponse{
		Filter:   request.GetFilter(),
		Nodes:    vulnz,
		PageInfo: pageInfo,
	}, nil
}

func toProtoTimestamp(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if !ts.Valid {
		return nil
	}
	return timestamppb.New(ts.Time)
}
