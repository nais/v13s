package grpcvulnerabilities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
		// if a workload does not have a sbom, the image name and tag will be nil from vulnerabilities_summary
		imageName := row.CurrentImageName
		if row.ImageName != nil {
			imageName = *row.ImageName
		}
		imageTag := row.CurrentImageTag
		if row.ImageTag != nil {
			imageTag = *row.ImageTag
		}
		return &vulnerabilities.WorkloadSummary{
			Id: row.ID.String(),
			Workload: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: imageName,
				ImageTag:  imageTag,
			},
			// TODO: Summary rows in the is not guaranteed to have a value, so we need to check if it's nil
			VulnerabilitySummary: &vulnerabilities.Summary{
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
			SbomStatus: sbomStatusInfo(row.WorkloadState, row.ImageState, row.SbomProcessingStartedAt),
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
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
		Critical:    row.Critical,
		High:        row.High,
		Medium:      row.Medium,
		Low:         row.Low,
		Unassigned:  row.Unassigned,
		Total:       row.Critical + row.High + row.Medium + row.Low + row.Unassigned,
		RiskScore:   row.RiskScore,
		LastUpdated: timestamppb.New(row.UpdatedAt.Time),
		HasSbom:     true,
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
	summary, err := s.querier.GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	var staleTag string
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("failed to get vulnerability summary for image: %w", err)
		}
		// No vulnerability summary for this exact tag yet (e.g. first-time scan in progress).
		// Fall through so we still populate workload_ref + workloads with SBOM state.
		// VulnerabilitySummary will be empty (&Summary{}) to preserve backward-compatible
		// semantics — nais/api cannot yet distinguish stale data from a real empty summary.
		//
		// TODO: activate stale-tag fallback once nais/api is updated. Before enabling,
		// these three call sites in nais/api/internal/vulnerability/queries.go must be updated:
		//   - GetImageHasSBOM (queries.go:156):        check StaleImageTag; return false when set
		//   - GetImageVulnerabilitySummary (queries.go:354): surface StaleImageTag to callers
		//   - ListWorkloadReferences (queries.go:25):  handle codes.NotFound explicitly
		//
		// staleSummary, fallbackErr := s.querier.GetLatestSummaryForImageName(ctx, sql.GetLatestSummaryForImageNameParams{
		// 	ImageName:  request.ImageName,
		// 	ExcludeTag: request.ImageTag,
		// })
		// if fallbackErr != nil && !errors.Is(fallbackErr, pgx.ErrNoRows) {
		// 	return nil, fmt.Errorf("failed to get fallback vulnerability summary for image: %w", fallbackErr)
		// }
		// if fallbackErr == nil {
		// 	summary = staleSummary
		// 	staleTag = staleSummary.ImageTag
		// }
		summary = nil
	}

	workloads, err := s.querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list workloads by image: %w", err)
	}

	workloadRefs := make([]*vulnerabilities.Workload, 0, len(workloads))
	worstStatus := vulnerabilities.SbomStatus_SBOM_STATUS_UNSPECIFIED
	var earliestProcessingStartedAt *timestamppb.Timestamp
	if len(workloads) > 0 {
		for _, w := range workloads {
			wl := &vulnerabilities.Workload{
				Cluster:   w.Cluster,
				Namespace: w.Namespace,
				Name:      w.Name,
				Type:      w.WorkloadType,
				ImageName: w.ImageName,
				ImageTag:  w.ImageTag,
			}
			status := deriveSbomStatus(w.State, w.ImageState)
			if sbomStatusPriority[status] > sbomStatusPriority[worstStatus] {
				worstStatus = status
			}
			if isPendingSbomStatus(status) && w.SbomProcessingStartedAt.Valid {
				t := timestamppb.New(w.SbomProcessingStartedAt.Time)
				if earliestProcessingStartedAt == nil || t.AsTime().Before(earliestProcessingStartedAt.AsTime()) {
					earliestProcessingStartedAt = t
				}
			}
			workloadRefs = append(workloadRefs, wl)
		}
	} else {
		img, imgErr := s.querier.GetImage(ctx, sql.GetImageParams{
			Name: request.ImageName,
			Tag:  request.ImageTag,
		})
		if imgErr != nil && !errors.Is(imgErr, pgx.ErrNoRows) {
			return nil, fmt.Errorf("failed to get image: %w", imgErr)
		}
		if imgErr == nil {
			worstStatus = deriveImageSbomStatus(&img.State)
			if isPendingSbomStatus(worstStatus) && img.SbomProcessingStartedAt.Valid {
				earliestProcessingStartedAt = timestamppb.New(img.SbomProcessingStartedAt.Time)
			}
		} else {
			worstStatus = vulnerabilities.SbomStatus_SBOM_STATUS_NO_SBOM
		}
	}
	var processingStartedAt *timestamppb.Timestamp
	if isPendingSbomStatus(worstStatus) {
		processingStartedAt = earliestProcessingStartedAt
	}
	worstSbomStatus := &vulnerabilities.SbomStatusInfo{
		Status:              worstStatus,
		ProcessingStartedAt: processingStartedAt,
	}

	// Default to empty summary to preserve backward-compatible semantics for existing
	// consumers (e.g. nais/api) that do not handle a nil VulnerabilitySummary.
	vulnSummary := &vulnerabilities.Summary{}
	if summary != nil {
		vulnSummary = &vulnerabilities.Summary{
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
		if staleTag != "" {
			vulnSummary.StaleImageTag = &staleTag
		}
	}

	return &vulnerabilities.GetVulnerabilitySummaryForImageResponse{
		VulnerabilitySummary: vulnSummary,
		WorkloadRef:          workloadRefs,
		SbomStatus:           worstSbomStatus,
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
				Id:                 row.CveID,
				Title:              row.CveTitle,
				Description:        row.CveDesc,
				Link:               row.CveLink,
				Severity:           vulnerabilities.Severity(row.Severity),
				References:         refs,
				Created:            timestamppb.New(row.CreatedAt.Time),
				LastUpdated:        timestamppb.New(row.UpdatedAt.Time),
				CvssScore:          row.CvssScore,
				EpssScore:          row.EpssScore,
				EpssPercentile:     row.EpssPercentile,
				HasKevEntry:        row.HasKevEntry,
				KnownRansomwareUse: row.KnownRansomwareUse,
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
