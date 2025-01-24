package grpcvulnerabilities

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"time"

	"github.com/nais/v13s/internal/database/sql"

	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	Db *sql.Queries
}

func (s *Server) ListVulnerabilitySummaries(ctx context.Context, request *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	summaries, err := s.Db.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
		Cluster:      request.Filter.Cluster,
		Namespace:    request.Filter.Namespace,
		WorkloadType: request.Filter.WorkloadType,
		WorkloadName: request.Filter.Workload,
		Limit:        limit,
		Offset:       offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	ws := collections.Map(summaries, func(row *sql.ListVulnerabilitySummariesRow) *vulnerabilities.WorkloadSummary {
		return &vulnerabilities.WorkloadSummary{
			Workload: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
			},
			VulnerabilitySummary: &vulnerabilities.Summary{
				Critical:    *row.Critical,
				High:        *row.High,
				Medium:      *row.Medium,
				Low:         *row.Low,
				Unassigned:  *row.Unassigned,
				RiskScore:   *row.RiskScore,
				LastUpdated: timestamppb.New(row.VulnerabilityUpdatedAt.Time),
			},
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, len(ws))
	if err != nil {
		return nil, err
	}

	response := &vulnerabilities.ListVulnerabilitySummariesResponse{
		WorkloadSummaries: ws,
		PageInfo:          pageInfo,
	}
	return response, nil
}

// TODO: if no summaries are found, handle this case by not returning the summary? and maybe handle it in the sql query, right now we return 0 on all fields
// TLDR: make distinction between no summary found and summary found with 0 values
func (s *Server) GetVulnerabilitySummary(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryRequest) (*vulnerabilities.GetVulnerabilitySummaryResponse, error) {
	sum, err := s.Db.GetVulnerabilitySummary(ctx, sql.GetVulnerabilitySummaryParams{
		Cluster:      request.Filter.Cluster,
		Namespace:    request.Filter.Namespace,
		WorkloadType: request.Filter.WorkloadType,
		WorkloadName: request.Filter.Workload,
	})

	if err != nil {
		return nil, err
	}

	var summary = vulnerabilities.Summary{
		Critical:    sum.CriticalVulnerabilities,
		High:        sum.HighVulnerabilities,
		Medium:      sum.MediumVulnerabilities,
		Low:         sum.LowVulnerabilities,
		Unassigned:  sum.UnassignedVulnerabilities,
		RiskScore:   sum.TotalRiskScore,
		LastUpdated: timestamppb.New(time.Now()),
	}

	response := &vulnerabilities.GetVulnerabilitySummaryResponse{
		Filter:               request.Filter,
		VulnerabilitySummary: &summary,
		WorkloadCount:        sum.WorkloadCount,
	}
	return response, nil
}
