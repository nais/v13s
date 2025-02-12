package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// TODO: add input validation for request, especially for filter values
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
		ImageName:         request.Filter.ImageName,
		ImageTag:          request.Filter.ImageTag,
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
				Cve: &vulnerabilities.Cve{
					Id:          row.CveID,
					Title:       row.CveTitle,
					Description: row.CveDesc,
					Link:        row.CveLink,
					Severity:    vulnerabilities.Severity(row.Severity),
				},
			},
		}
	})

	total, err := s.db.CountVulnerabilities(ctx, sql.CountVulnerabilitiesParams{
		Cluster:           request.Filter.Cluster,
		Namespace:         request.Filter.Namespace,
		WorkloadType:      request.Filter.WorkloadType,
		WorkloadName:      request.Filter.Workload,
		IncludeSuppressed: request.Suppressed,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListVulnerabilitiesResponse{
		Filter:   request.Filter,
		Nodes:    vulnz,
		PageInfo: pageInfo,
	}, nil
}

// TODO: do we want image_name and image_tag as filter aswell? must update sql query
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

	summary := &vulnerabilities.Summary{}
	if sum != nil {
		summary.Critical = sum.CriticalVulnerabilities
		summary.High = sum.HighVulnerabilities
		summary.Medium = sum.MediumVulnerabilities
		summary.Low = sum.LowVulnerabilities
		summary.Unassigned = sum.UnassignedVulnerabilities
		summary.RiskScore = sum.TotalRiskScore
		summary.HasSbom = true
	}

	response := &vulnerabilities.GetVulnerabilitySummaryResponse{
		Filter:               request.Filter,
		VulnerabilitySummary: summary,
		WorkloadCount:        sum.WorkloadCount,
	}
	return response, nil
}

func (s *Server) GetVulnerabilitySummaryForImage(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryForImageRequest) (*vulnerabilities.GetVulnerabilitySummaryForImageResponse, error) {
	summary, err := s.db.GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &vulnerabilities.GetVulnerabilitySummaryForImageResponse{
				VulnerabilitySummary: &vulnerabilities.Summary{},
				WorkloadRef:          make([]*vulnerabilities.Workload, 0),
			}, nil
		}

		return nil, fmt.Errorf("failed to get vulnerability summary for image: %w", err)
	}
	workloads, err := s.db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workloads by image: %w", err)
	}

	refs := make([]*vulnerabilities.Workload, 0)
	for _, w := range workloads {
		refs = append(refs, &vulnerabilities.Workload{
			Cluster:   w.Cluster,
			Namespace: w.Namespace,
			Name:      w.Name,
			Type:      w.WorkloadType,
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
	}

	vulnSummary := &vulnerabilities.Summary{}
	if summary != nil {
		vulnSummary = &vulnerabilities.Summary{
			Critical:    summary.Critical,
			High:        summary.High,
			Medium:      summary.Medium,
			Low:         summary.Low,
			Unassigned:  summary.Unassigned,
			RiskScore:   summary.RiskScore,
			LastUpdated: timestamppb.New(summary.UpdatedAt.Time),
			HasSbom:     true,
		}
	}

	return &vulnerabilities.GetVulnerabilitySummaryForImageResponse{
		VulnerabilitySummary: vulnSummary,
		WorkloadRef:          refs,
	}, nil
}
