package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/nais/v13s/pkg/api/vulnerabilitiespb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) ListVulnerabilitySummaries(ctx context.Context, request *vulnerabilitiespb.ListVulnerabilitySummariesRequest) (*vulnerabilitiespb.ListVulnerabilitySummariesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.GetFilter() == nil {
		request.Filter = &vulnerabilitiespb.Filter{}
	}

	since := pgtype.Timestamptz{}
	if request.GetSince() != nil {
		since.Time = request.GetSince().AsTime()
		since.Valid = true
	}

	// TODO: extract this to a function
	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}
	summaries, err := s.querier.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
		ImageName:     request.GetFilter().ImageName,
		ImageTag:      request.GetFilter().ImageTag,
		OrderBy:       sanitizeOrderBy(request.OrderBy, vulnerabilities.OrderByCritical),
		Limit:         limit,
		Offset:        offset,
		Since:         since,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	total := 0
	ws := collections.Map(summaries, func(row *sql.ListVulnerabilitySummariesRow) *vulnerabilitiespb.WorkloadSummary {
		total = int(row.TotalCount)
		// if a workload does not have a sbom, the image name and tag will be nil from vulnerabilities_summary
		imageName := row.CurrentImageName
		if row.ImageName != nil {
			imageName = *row.ImageName
		}
		imageTag := row.CurrentImageTag
		if row.ImageTag != nil {
			imageTag = *row.ImageTag
		}
		return &vulnerabilitiespb.WorkloadSummary{
			Id: row.ID.String(),
			Workload: &vulnerabilitiespb.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: imageName,
				ImageTag:  imageTag,
			},
			// TODO: Summary rows in the is not guaranteed to have a value, so we need to check if it's nil
			VulnerabilitySummary: &vulnerabilitiespb.Summary{
				Critical:    safeInt(row.Critical),
				High:        safeInt(row.High),
				Medium:      safeInt(row.Medium),
				Low:         safeInt(row.Low),
				Unassigned:  safeInt(row.Unassigned),
				Total:       safeInt(row.Critical) + safeInt(row.High) + safeInt(row.Medium) + safeInt(row.Low) + safeInt(row.Unassigned),
				RiskScore:   safeInt(row.RiskScore),
				LastUpdated: timestamppb.New(row.SummaryUpdatedAt.Time),
				HasSbom:     row.HasSbom,
			},
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
	if err != nil {
		return nil, err
	}
	response := &vulnerabilitiespb.ListVulnerabilitySummariesResponse{
		Nodes:    ws,
		PageInfo: pageInfo,
	}
	return response, nil
}

// TODO: if no summaries are found, handle this case by not returning the summary? and maybe handle it in the sql query, right now we return 0 on all fields
// TLDR: make distinction between no summary found and summary found with 0 values
func (s *Server) GetVulnerabilitySummary(ctx context.Context, request *vulnerabilitiespb.GetVulnerabilitySummaryRequest) (*vulnerabilitiespb.GetVulnerabilitySummaryResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilitiespb.Filter{}
	}

	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}
	row, err := s.querier.GetVulnerabilitySummary(ctx, sql.GetVulnerabilitySummaryParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
	})

	if err != nil {
		return nil, err
	}

	if row == nil {
		row = &sql.GetVulnerabilitySummaryRow{}
	}

	summary := &vulnerabilitiespb.Summary{
		Critical:   row.Critical,
		High:       row.High,
		Medium:     row.Medium,
		Low:        row.Low,
		Unassigned: row.Unassigned,
		Total:      row.Critical + row.High + row.Medium + row.Low + row.Unassigned,
		RiskScore:  row.RiskScore,
		HasSbom:    true,
	}

	var coverage float32
	if row.WorkloadCount > 0 && row.WorkloadWithSbom > 0 {
		coverage = float32(row.WorkloadWithSbom) / float32(row.WorkloadCount) * 100
	}

	response := &vulnerabilitiespb.GetVulnerabilitySummaryResponse{
		Filter:               request.GetFilter(),
		VulnerabilitySummary: summary,
		WorkloadCount:        row.WorkloadCount,
		SbomCount:            row.WorkloadWithSbom,
		Coverage:             coverage,
	}
	return response, nil
}

func (s *Server) GetVulnerabilitySummaryTimeSeries(ctx context.Context, request *vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesRequest) (*vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilitiespb.Filter{}
	}

	since := pgtype.Timestamptz{}
	if request.GetSince() != nil {
		since.Time = request.GetSince().AsTime()
		since.Valid = true
	}
	wTypes := []string{"app", "job"}
	if request.GetFilter().GetWorkloadType() != "" {
		wTypes = []string{request.GetFilter().GetWorkloadType()}
	}

	timeSeries, err := s.querier.GetVulnerabilitySummaryTimeSeries(ctx, sql.GetVulnerabilitySummaryTimeSeriesParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
		Since:         since,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	points := collections.Map(timeSeries, func(row *sql.GetVulnerabilitySummaryTimeSeriesRow) *vulnerabilitiespb.VulnerabilitySummaryPoint {
		return &vulnerabilitiespb.VulnerabilitySummaryPoint{
			Critical:      row.Critical,
			High:          row.High,
			Medium:        row.Medium,
			Low:           row.Low,
			Unassigned:    row.Unassigned,
			Total:         row.Critical + row.High + row.Medium + row.Low + row.Unassigned,
			RiskScore:     row.RiskScore,
			WorkloadCount: row.WorkloadCount,
			BucketTime:    timestamppb.New(row.SnapshotDate.Time),
		}
	})
	return &vulnerabilitiespb.GetVulnerabilitySummaryTimeSeriesResponse{
		Points: points,
	}, nil
}

func (s *Server) GetVulnerabilitySummaryForImage(ctx context.Context, request *vulnerabilitiespb.GetVulnerabilitySummaryForImageRequest) (*vulnerabilitiespb.GetVulnerabilitySummaryForImageResponse, error) {
	summary, err := s.querier.GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &vulnerabilitiespb.GetVulnerabilitySummaryForImageResponse{
				VulnerabilitySummary: &vulnerabilitiespb.Summary{},
				WorkloadRef:          make([]*vulnerabilitiespb.Workload, 0),
			}, nil
		}

		return nil, fmt.Errorf("failed to get vulnerability summary for image: %w", err)
	}
	workloads, err := s.querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workloads by image: %w", err)
	}

	refs := make([]*vulnerabilitiespb.Workload, 0)
	for _, w := range workloads {
		refs = append(refs, &vulnerabilitiespb.Workload{
			Cluster:   w.Cluster,
			Namespace: w.Namespace,
			Name:      w.Name,
			Type:      w.WorkloadType,
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
	}

	vulnSummary := &vulnerabilitiespb.Summary{}
	if summary != nil {
		vulnSummary = &vulnerabilitiespb.Summary{
			Critical:    summary.Critical,
			High:        summary.High,
			Medium:      summary.Medium,
			Low:         summary.Low,
			Unassigned:  summary.Unassigned,
			Total:       summary.Critical + summary.High + summary.Medium + summary.Low + summary.Unassigned,
			RiskScore:   summary.RiskScore,
			LastUpdated: timestamppb.New(summary.UpdatedAt.Time),
			HasSbom:     true,
		}
	}

	return &vulnerabilitiespb.GetVulnerabilitySummaryForImageResponse{
		VulnerabilitySummary: vulnSummary,
		WorkloadRef:          refs,
	}, nil
}
