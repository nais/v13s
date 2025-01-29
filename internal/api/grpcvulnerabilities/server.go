package grpcvulnerabilities

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/database/sql"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"

	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	db sql.Querier
}

func NewServer(db sql.Querier) *Server {
	return &Server{
		db: db,
	}
}

func (s *Server) ListVulnerabilities(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesRequest) (*vulnerabilities.ListVulnerabilitiesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.Filter == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	v, err := s.db.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{
		Cluster:           request.Filter.Cluster,
		Namespace:         request.Filter.Namespace,
		WorkloadType:      request.Filter.WorkloadType,
		WorkloadName:      request.Filter.Workload,
		IncludeSuppressed: request.Suppressed,
		Limit:             limit,
		Offset:            offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	vulnz := collections.Map(v, func(row *sql.ListVulnerabilitiesRow) *vulnerabilities.Finding {
		return &vulnerabilities.Finding{
			WorkloadRef: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: row.ImageName,
				ImageTag:  row.ImageTag,
			},
			Vulnerability: &vulnerabilities.Vulnerability{
				Package:    row.Package,
				Suppressed: &row.Suppressed,
				Cwe: &vulnerabilities.Cwe{
					Id:          row.CweID,
					Title:       row.CweTitle,
					Description: row.CweDesc,
					Link:        row.CweLink,
					Severity:    vulnerabilities.Severity(row.Severity),
				},
			},
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, len(vulnz))
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListVulnerabilitiesResponse{
		Filter:   request.Filter,
		Nodes:    vulnz,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) ListVulnerabilitySummaries(ctx context.Context, request *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.Filter == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	summaries, err := s.db.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
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
	if request.Filter == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	sum, err := s.db.GetVulnerabilitySummary(ctx, sql.GetVulnerabilitySummaryParams{
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
