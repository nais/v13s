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
	"google.golang.org/protobuf/types/known/timestamppb"
	"sort"
	"time"
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

	summary := &vulnerabilities.Summary{
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

	response := &vulnerabilities.GetVulnerabilitySummaryResponse{
		Filter:               request.GetFilter(),
		VulnerabilitySummary: summary,
		WorkloadCount:        row.WorkloadCount,
		SbomCount:            row.WorkloadWithSbom,
		Coverage:             coverage,
	}
	return response, nil
}

// TODO: validate input params before using in db query
func (s *Server) GetVulnerabilitySummaryTimeSeries(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryTimeSeriesRequest) (*vulnerabilities.GetVulnerabilitySummaryTimeSeriesResponse, error) {
	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
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
	/*	groupBy := make([]string, 0)
		if request.GetGroupBy() != "" {
			groupBy = []string{request.GetGroupBy()}
		}
		resolution := ""
		if request.Resolution != nil {
			switch request.GetResolution() {
			case vulnerabilities.Resolution_HOUR:
				resolution = "hour"
			case vulnerabilities.Resolution_DAY:
				resolution = "day"
			case vulnerabilities.Resolution_WEEK:
				resolution = "week"
			case vulnerabilities.Resolution_MONTH:
				resolution = "month"
			}
		}

	*/
	sums, err := s.querier.ListVulnerabilitySummaryTimeseries(ctx, sql.ListVulnerabilitySummaryTimeseriesParams{
		Cluster:       request.GetFilter().Cluster,
		Namespace:     request.GetFilter().Namespace,
		WorkloadTypes: wTypes,
		WorkloadName:  request.GetFilter().Workload,
		Since:         since,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability summaries: %w", err)
	}

	type Day = time.Time
	type WorkloadId = string
	type Summary = *sql.ListVulnerabilitySummaryTimeseriesRow

	yolo := make(map[Day]map[WorkloadId]Summary)

	type WorkloadBucket struct {
		WorkloadId WorkloadId
		Points     []Summary
	}

	type Buckets map[Day]map[WorkloadId]WorkloadBucket

	buckets := make(Buckets)
	for _, sum := range sums {
		day := sum.SummaryUpdatedAt.Time.Truncate(24 * time.Hour)
		key := day
		workloadId := fmt.Sprintf("%s:%s:%s:%s", sum.Cluster, sum.Namespace, sum.WorkloadType, sum.WorkloadName)

		// does day exist in buckets?
		if _, exists := buckets[key]; !exists {
			buckets[day] = make(map[WorkloadId]WorkloadBucket)
		}
		// does workload exist in buckets?
		if _, exists := buckets[key][workloadId]; !exists {
			buckets[key][workloadId] = WorkloadBucket{
				WorkloadId: workloadId,
				Points:     []Summary{},
			}
		}
		// add summary to workload bucket
		bucket := buckets[key][workloadId]
		bucket.Points = append(bucket.Points, sum)
		buckets[key][workloadId] = bucket
	}

	type SummaryPoint struct {
		Critical      int32
		High          int32
		Medium        int32
		Low           int32
		Unassigned    int32
		RiskScore     int32
		WorkloadCount int32
	}

	type SummaryBuckets map[Day]SummaryPoint

	summaryBuckets := make(SummaryBuckets)

	points := make([]*vulnerabilities.VulnerabilitySummaryPoint, 0)

	for day, workloads := range buckets {
		if _, ok := summaryBuckets[day]; !ok {
			summaryBuckets[day] = SummaryPoint{}
		}
		summaryPoint := summaryBuckets[day]
		for _, workload := range workloads {
			var summary Summary
			for _, point := range workload.Points {
				if summary == nil {
					summary = point
				}
				if point.SummaryUpdatedAt.Time.After(summary.SummaryUpdatedAt.Time) {
					if *point.RiskScore > 0 {
						summary = point
					}
				}
			}
			if summary != nil && summary.HasSbom {
				if summary.Critical == nil {
					fmt.Printf("%+v\n", summary)
				}
				summaryPoint.Critical += *summary.Critical
				summaryPoint.High += *summary.High
				summaryPoint.Medium += *summary.Medium
				summaryPoint.Low += *summary.Low
				summaryPoint.Unassigned += *summary.Unassigned
				summaryPoint.RiskScore += *summary.RiskScore
				summaryPoint.WorkloadCount += 1
			}
		}
		//summaryBuckets[day] = summaryPoint
		points = append(points, &vulnerabilities.VulnerabilitySummaryPoint{
			Critical:      summaryPoint.Critical,
			High:          summaryPoint.High,
			Medium:        summaryPoint.Medium,
			Low:           summaryPoint.Low,
			Unassigned:    summaryPoint.Unassigned,
			Total:         summaryPoint.Critical + summaryPoint.High + summaryPoint.Medium + summaryPoint.Low + summaryPoint.Unassigned,
			RiskScore:     summaryPoint.RiskScore,
			WorkloadCount: summaryPoint.WorkloadCount,
			BucketTime:    timestamppb.New(day),
			Cluster:       request.GetFilter().Cluster,
			Namespace:     request.GetFilter().Namespace,
		})
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].BucketTime.AsTime().Before(points[j].BucketTime.AsTime())
	})

	fmt.Printf("%+v\n", yolo)

	/*	timeSeries, err := s.querier.GetVulnerabilitySummaryTimeSeries(ctx, sql.GetVulnerabilitySummaryTimeSeriesParams{
			Cluster:       request.GetFilter().Cluster,
			Namespace:     request.GetFilter().Namespace,
			WorkloadTypes: wTypes,
			WorkloadName:  request.GetFilter().Workload,
			Since:         since,
			Resolution:    resolution,
			GroupBy:       groupBy,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get vulnerability summary time series: %w", err)
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
				BucketTime:    timestamppb.New(row.BucketTime.Time),
				Cluster:       &row.GroupCluster,
				Namespace:     &row.GroupNamespace,
				WorkloadType:  &row.GroupWorkloadType,
			}
		})*/
	return &vulnerabilities.GetVulnerabilitySummaryTimeSeriesResponse{
		Points: points,
	}, nil
}

func (s *Server) GetVulnerabilitySummaryForImage(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryForImageRequest) (*vulnerabilities.GetVulnerabilitySummaryForImageResponse, error) {
	summary, err := s.querier.GetVulnerabilitySummaryForImage(ctx, sql.GetVulnerabilitySummaryForImageParams{
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
	}

	return &vulnerabilities.GetVulnerabilitySummaryForImageResponse{
		VulnerabilitySummary: vulnSummary,
		WorkloadRef:          refs,
	}, nil
}
