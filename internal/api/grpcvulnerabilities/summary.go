package grpcvulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type StaleResult struct {
	Severity vulnerabilities.StaleSeverity
	Reason   string
	Code     vulnerabilities.StaleReasonCode
}

func CalculateStaleSeverity(staleSummary bool, hasSbom bool, imageState sql.NullImageState, workloadState *sql.WorkloadState, currentTag, fallbackTag string) StaleResult {
	if workloadState != nil && *workloadState == sql.WorkloadStateNoAttestation {
		if fallbackTag != "" && fallbackTag != currentTag {
			return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("no attestation found for image tag %s, showing data from %s", currentTag, fallbackTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_NO_ATTESTATION}
		}
		return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("no attestation found for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_NO_ATTESTATION}
	}

	// A current summary cannot be up to date if we do not have an SBOM for the image.
	if !staleSummary && !hasSbom {
		if imageState.Valid {
			switch imageState.ImageState {
			case sql.ImageStateInitialized, sql.ImageStateResync, sql.ImageStateOutdated:
				return StaleResult{vulnerabilities.StaleSeverity_STALE_PROCESSING, fmt.Sprintf("SBOM for tag %s is being processed", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_PROCESSING}
			case sql.ImageStateFailed:
				return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("failed to upload SBOM for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_SBOM_UPLOAD_FAILED}
			case sql.ImageStateUntracked:
				return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("SBOM not found for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_NO_SBOM}
			}
		}
		return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("SBOM not found for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_NO_SBOM}
	}

	// If we have a current summary (not using fallback), return STALE_NONE
	if !staleSummary {
		return StaleResult{vulnerabilities.StaleSeverity_STALE_NONE, "SBOM is up to date", vulnerabilities.StaleReasonCode_STALE_REASON_CODE_UP_TO_DATE}
	}

	// From here on, we know staleSummary is true (we're using fallback data)
	// Check image state to determine why we don't have current data
	if imageState.Valid {
		switch imageState.ImageState {
		case sql.ImageStateUntracked:
			if !hasSbom {
				return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("SBOM not found for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_NO_SBOM}
			}
			// Has fallback SBOM - fall through to processing message
		case sql.ImageStateFailed:
			// Failed state is permanent - show appropriate message
			if fallbackTag != "" && fallbackTag != currentTag {
				return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("failed to upload SBOM for image tag %s, showing data from %s", currentTag, fallbackTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_SBOM_UPLOAD_FAILED}
			}
			return StaleResult{vulnerabilities.StaleSeverity_STALE_PERMANENT, fmt.Sprintf("failed to upload SBOM for image tag %s", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_SBOM_UPLOAD_FAILED}
		}
	}

	// Default stale processing message
	if fallbackTag != "" && fallbackTag != currentTag {
		return StaleResult{vulnerabilities.StaleSeverity_STALE_PROCESSING, fmt.Sprintf("Tag %s is processing, data from %s", currentTag, fallbackTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_PROCESSING_WITH_FALLBACK}
	}

	return StaleResult{vulnerabilities.StaleSeverity_STALE_PROCESSING, fmt.Sprintf("SBOM for tag %s is being processed", currentTag), vulnerabilities.StaleReasonCode_STALE_REASON_CODE_PROCESSING}
}

func (s *Server) ListVulnerabilitySummaries(ctx context.Context, request *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	since := pgtype.Timestamptz{}
	if request.GetSince() != nil {
		since.Time = request.GetSince().AsTime()
		since.Valid = true
	}

	summaries, err := s.querier.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: request.Filter.GetWorkloadTypes(),
		WorkloadName:  request.GetFilter().Workload,
		ImageName:     request.GetFilter().ImageName,
		ImageTag:      request.GetFilter().ImageTag,
		OrderBy:       SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderByCritical),
		Limit:         limit,
		Offset:        offset,
		Since:         since,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	total := 0
	ws := collections.Map(summaries, func(row *sql.ListVulnerabilitySummariesRow) *vulnerabilities.WorkloadSummary {
		total = int(row.TotalCount)
		summary := &vulnerabilities.Summary{
			Critical:   row.Critical,
			High:       row.High,
			Medium:     row.Medium,
			Low:        row.Low,
			Unassigned: row.Unassigned,
			Total:      row.Critical + row.High + row.Medium + row.Low + row.Unassigned,
			RiskScore:  row.RiskScore,
			HasSbom:    row.HasSbom,
		}
		if row.HasSbom && row.SummaryUpdatedAt.Valid {
			summary.LastUpdated = timestamppb.New(row.SummaryUpdatedAt.Time)
		}

		stale := CalculateStaleSeverity(row.StaleSummary, row.HasSbom, row.ImageState, &row.WorkloadState, row.CurrentImageTag, row.ImageTag)

		return &vulnerabilities.WorkloadSummary{
			Id: row.ID.String(),
			Workload: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: row.CurrentImageName,
				ImageTag:  row.CurrentImageTag,
			},
			VulnerabilitySummary: summary,
			StaleSeverity:        stale.Severity,
			StaleReason:          stale.Reason,
			StaleReasonCode:      stale.Code,
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, total)
	if err != nil {
		return nil, err
	}
	response := &vulnerabilities.ListVulnerabilitySummariesResponse{
		Nodes:    ws,
		PageInfo: pageInfo,
	}
	return response, nil
}

// TODO: if no summaries are found, handle this case by not returning the summary? and maybe handle it in the sql query, right now we return 0 on all fields
// TLDR: make distinction between no summary found and summary found with 0 values
func (s *Server) GetVulnerabilitySummary(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryRequest) (*vulnerabilities.GetVulnerabilitySummaryResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	row, err := s.querier.GetVulnerabilitySummary(ctx, sql.GetVulnerabilitySummaryParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: request.Filter.GetWorkloadTypes(),
		WorkloadName:  request.GetFilter().Workload,
	})
	if err != nil {
		return nil, err
	}

	if row == nil {
		row = &sql.GetVulnerabilitySummaryRow{}
	}

	summary := &vulnerabilities.Summary{
		Critical:   row.Critical,
		High:       row.High,
		Medium:     row.Medium,
		Low:        row.Low,
		Unassigned: row.Unassigned,
		Total:      row.Critical + row.High + row.Medium + row.Low + row.Unassigned,
		RiskScore:  row.RiskScore,
		HasSbom:    row.WorkloadWithSbom > 0,
	}

	if row.UpdatedAt.Valid {
		summary.LastUpdated = timestamppb.New(row.UpdatedAt.Time)
	}

	var coverage float32
	if row.WorkloadCount > 0 && row.WorkloadWithSbom > 0 {
		coverage = float32(row.WorkloadWithSbom) / float32(row.WorkloadCount) * 100
	}

	response := &vulnerabilities.GetVulnerabilitySummaryResponse{
		Filter:               request.GetFilter(),
		VulnerabilitySummary: summary,
		WorkloadCount:        row.WorkloadCount,
		SbomCount:            row.WorkloadWithSbom,
		Coverage:             coverage,
	}
	return response, nil
}

func (s *Server) GetVulnerabilitySummaryTimeSeries(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryTimeSeriesRequest) (*vulnerabilities.GetVulnerabilitySummaryTimeSeriesResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	since := pgtype.Timestamptz{}
	if request.GetSince() != nil {
		since.Time = request.GetSince().AsTime()
		since.Valid = true
	}

	timeSeries, err := s.querier.GetVulnerabilitySummaryTimeSeries(ctx, sql.GetVulnerabilitySummaryTimeSeriesParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: request.Filter.GetWorkloadTypes(),
		WorkloadName:  request.GetFilter().Workload,
		Since:         since,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	points := collections.Map(timeSeries, func(row *sql.GetVulnerabilitySummaryTimeSeriesRow) *vulnerabilities.VulnerabilitySummaryPoint {
		return &vulnerabilities.VulnerabilitySummaryPoint{
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
	return &vulnerabilities.GetVulnerabilitySummaryTimeSeriesResponse{
		Points: points,
	}, nil
}

func (s *Server) GetVulnerabilitySummaryForImage(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryForImageRequest) (*vulnerabilities.GetVulnerabilitySummaryForImageResponse, error) {
	row, err := s.querier.GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability summary for image: %w", err)
	}

	workloads, err := s.querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
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

	vulnSummary := &vulnerabilities.Summary{
		HasSbom: row.HasSbom,
	}
	if row.HasSbom {
		vulnSummary.Critical = row.Critical
		vulnSummary.High = row.High
		vulnSummary.Medium = row.Medium
		vulnSummary.Low = row.Low
		vulnSummary.Unassigned = row.Unassigned
		vulnSummary.Total = row.Critical + row.High + row.Medium + row.Low + row.Unassigned
		vulnSummary.RiskScore = row.RiskScore
		if row.UpdatedAt.Valid {
			vulnSummary.LastUpdated = timestamppb.New(row.UpdatedAt.Time)
		}
	}

	stale := CalculateStaleSeverity(row.IsSummaryStale, row.HasSbom, row.ImageState, nil, request.ImageTag, row.ImageTag)

	return &vulnerabilities.GetVulnerabilitySummaryForImageResponse{
		VulnerabilitySummary: vulnSummary,
		WorkloadRef:          refs,
		StaleSeverity:        stale.Severity,
		StaleReason:          stale.Reason,
		StaleReasonCode:      stale.Code,
	}, nil
}

func (s *Server) ListCveSummaries(ctx context.Context, request *vulnerabilities.ListCveSummariesRequest) (*vulnerabilities.ListCveSummariesResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	excludeNamespaces := request.GetExcludeNamespaces()
	if excludeNamespaces == nil {
		excludeNamespaces = []string{}
	}

	excludeClusters := request.GetExcludeClusters()
	if excludeClusters == nil {
		excludeClusters = []string{}
	}

	cveSummaries, err := s.querier.ListCveSummaries(ctx, sql.ListCveSummariesParams{
		Cluster:           request.GetFilter().Cluster,
		Namespace:         request.GetFilter().Namespace,
		WorkloadName:      request.GetFilter().Workload,
		WorkloadTypes:     request.GetFilter().GetWorkloadTypes(),
		ImageName:         request.GetFilter().ImageName,
		ImageTag:          request.GetFilter().ImageTag,
		ExcludeClusters:   excludeClusters,
		ExcludeNamespaces: excludeNamespaces,
		IncludeSuppressed: request.IncludeSuppressed,
		OrderBy:           SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderByAffectedWorkloads),
		Limit:             request.Limit,
		Offset:            request.Offset,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list cve summaries: "+err.Error())
	}

	total := 0
	vulnCveSummaries := collections.Map(cveSummaries, func(row *sql.ListCveSummariesRow) *vulnerabilities.CveSummary {
		total = int(row.TotalCount)
		refs := map[string]string{}
		_ = json.Unmarshal(row.Refs, &refs)

		return &vulnerabilities.CveSummary{
			Cve: &vulnerabilities.Cve{
				Id:          row.CveID,
				Title:       row.CveTitle,
				Description: row.CveDesc,
				Link:        row.CveLink,
				Severity:    vulnerabilities.Severity(row.Severity),
				References:  refs,
				Created:     timestamppb.New(row.CreatedAt.Time),
				LastUpdated: timestamppb.New(row.UpdatedAt.Time),
				CvssScore:   row.CvssScore,
			},
			AffectedWorkloads: row.AffectedWorkloads,
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, total)
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListCveSummariesResponse{
		Nodes:    vulnCveSummaries,
		PageInfo: pageInfo,
	}, nil
}
