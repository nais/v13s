package grpcvulnerabilities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/emicklei/pgtalk/convert"
	"github.com/google/uuid"
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

// TODO: use status.Errorf(codes.NotFound ...) and such for errors
func (s *Server) ListVulnerabilities(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesRequest) (*vulnerabilities.ListVulnerabilitiesResponse, error) {
	// TODO: add input validation for request, especially for filter values
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	v, err := s.querier.ListVulnerabilities(ctx, sql.ListVulnerabilitiesParams{
		Cluster:           request.GetFilter().Cluster,
		Namespace:         request.GetFilter().Namespace,
		WorkloadType:      request.GetFilter().FuzzyWorkloadType(),
		WorkloadName:      request.GetFilter().Workload,
		ImageName:         request.GetFilter().ImageName,
		ImageTag:          request.GetFilter().ImageTag,
		IncludeSuppressed: request.IncludeSuppressed,
		OrderBy:           SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
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
				Id:      row.ID.String(),
				Package: row.Package,
				Suppression: toSuppression(
					row.Suppressed,
					row.Reason.VulnerabilitySuppressReason,
					row.ReasonText,
					row.SuppressedBy,
					row.SuppressedAt.Time,
				),
				Created:       timestamppb.New(row.CreatedAt.Time),
				LastUpdated:   timestamppb.New(row.UpdatedAt.Time),
				LatestVersion: row.LatestVersion,
				SeveritySince: timestamppb.New(row.SeveritySince.Time),
				CvssScore:     row.CvssScore,
				Cve: &vulnerabilities.Cve{
					Id:          row.CveID,
					Title:       row.CveTitle,
					Description: row.CveDesc,
					Link:        row.CveLink,
					Severity:    vulnerabilities.Severity(row.Severity),
					Created:     timestamppb.New(row.CveCreatedAt.Time),
					LastUpdated: timestamppb.New(row.CveUpdatedAt.Time),
				},
			},
		}
	})

	total, err := s.querier.CountVulnerabilities(ctx, sql.CountVulnerabilitiesParams{
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

	return &vulnerabilities.ListVulnerabilitiesResponse{
		Filter:   request.GetFilter(),
		Nodes:    vulnz,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) ListVulnerabilitiesForImage(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesForImageRequest) (*vulnerabilities.ListVulnerabilitiesForImageResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	vulnz, err := s.querier.ListVulnerabilitiesForImage(ctx, sql.ListVulnerabilitiesForImageParams{
		ImageName:         request.GetImageName(),
		ImageTag:          request.GetImageTag(),
		IncludeSuppressed: &request.IncludeSuppressed,
		Offset:            offset,
		Limit:             limit,
		OrderBy:           SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
		Since:             timestamptzFromProto(request.GetSince()),
		Severity:          toInt32Ptr(request.Severity),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities for image: %w", err)
	}

	total := 0
	nodes := collections.Map(vulnz, func(row *sql.ListVulnerabilitiesForImageRow) *vulnerabilities.Vulnerability {
		total = int(row.TotalCount)
		refs := map[string]string{}
		_ = json.Unmarshal(row.CveRefs, &refs)

		return &vulnerabilities.Vulnerability{
			Id:      row.ID.String(),
			Package: row.Package,
			Suppression: toSuppression(
				row.Suppressed,
				row.Reason.VulnerabilitySuppressReason,
				row.ReasonText,
				row.SuppressedBy,
				row.SuppressedAt.Time,
			),
			Created:       timestamppb.New(row.CreatedAt.Time),
			LastUpdated:   timestamppb.New(row.UpdatedAt.Time),
			LatestVersion: row.LatestVersion,
			SeveritySince: timestamppb.New(row.SeveritySince.Time),
			CvssScore:     row.CvssScore,
			Cve: &vulnerabilities.Cve{
				Id:          row.CveID,
				Title:       row.CveTitle,
				Description: row.CveDesc,
				Link:        row.CveLink,
				Severity:    vulnerabilities.Severity(row.Severity),
				References:  refs,
				Created:     timestamppb.New(row.CveCreatedAt.Time),
				LastUpdated: timestamppb.New(row.CveUpdatedAt.Time),
			},
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, total)
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListVulnerabilitiesForImageResponse{
		Nodes:    nodes,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) ListSeverityVulnerabilitiesSince(ctx context.Context, request *vulnerabilities.ListSeverityVulnerabilitiesSinceRequest) (*vulnerabilities.ListSeverityVulnerabilitiesSinceResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	if request.GetFilter() == nil {
		request.Filter = &vulnerabilities.Filter{}
	}

	v, err := s.querier.ListSeverityVulnerabilitiesSince(ctx, sql.ListSeverityVulnerabilitiesSinceParams{
		Cluster:           request.GetFilter().Cluster,
		Namespace:         request.GetFilter().Namespace,
		WorkloadType:      request.GetFilter().FuzzyWorkloadType(),
		WorkloadName:      request.GetFilter().Workload,
		ImageName:         request.GetFilter().ImageName,
		IncludeSuppressed: request.IncludeSuppressed,
		OrderBy:           SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeveritySince),
		Since:             timestamptzFromProto(request.GetSince()),
		Limit:             limit,
		Offset:            offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerabilities: %w", err)
	}

	vulnz := collections.Map(v, func(row *sql.ListSeverityVulnerabilitiesSinceRow) *vulnerabilities.Finding {
		return &vulnerabilities.Finding{
			WorkloadRef: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: row.ImageName,
			},
			Vulnerability: &vulnerabilities.Vulnerability{
				Id:      row.ID.String(),
				Package: row.Package,
				Suppression: toSuppression(
					row.Suppressed,
					row.Reason.VulnerabilitySuppressReason,
					row.ReasonText,
					row.SuppressedBy,
					row.SuppressedAt.Time,
				),
				Created:       timestamppb.New(row.CreatedAt.Time),
				LastUpdated:   timestamppb.New(row.UpdatedAt.Time),
				SeveritySince: timestamppb.New(row.SeveritySince.Time),
				LastSeverity:  &row.LastSeverity,
				Cve: &vulnerabilities.Cve{
					Id:          row.CveID,
					Title:       row.CveTitle,
					Description: row.CveDesc,
					Link:        row.CveLink,
					Severity:    vulnerabilities.Severity(row.Severity),
					Created:     timestamppb.New(row.CveCreatedAt.Time),
					LastUpdated: timestamppb.New(row.CveUpdatedAt.Time),
				},
			},
		}
	})

	total, err := s.querier.CountVulnerabilities(ctx, sql.CountVulnerabilitiesParams{
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

	return &vulnerabilities.ListSeverityVulnerabilitiesSinceResponse{
		Filter:   request.GetFilter(),
		Nodes:    vulnz,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) ListSuppressedVulnerabilities(ctx context.Context, request *vulnerabilities.ListSuppressedVulnerabilitiesRequest) (*vulnerabilities.ListSuppressedVulnerabilitiesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	filter := request.GetFilter()
	suppressed, err := s.querier.ListSuppressedVulnerabilities(ctx, sql.ListSuppressedVulnerabilitiesParams{
		Cluster:   filter.Cluster,
		Namespace: filter.Namespace,
		ImageName: filter.ImageName,
		ImageTag:  filter.ImageTag,
		Offset:    offset,
		Limit:     limit,
		OrderBy:   SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
	})
	if err != nil {
		return nil, fmt.Errorf("list suppressed vulnerabilities: %w", err)
	}

	total, err := s.querier.CountSuppressedVulnerabilities(ctx, sql.CountSuppressedVulnerabilitiesParams{
		Cluster:      filter.Cluster,
		Namespace:    filter.Namespace,
		WorkloadType: filter.FuzzyWorkloadType(),
		WorkloadName: filter.Workload,
		ImageName:    filter.ImageName,
		ImageTag:     filter.ImageTag,
	})
	if err != nil {
		return nil, fmt.Errorf("count suppressed vulnerabilities: %w", err)
	}

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
	if err != nil {
		return nil, err
	}

	nodes := collections.Map(suppressed, func(row *sql.ListSuppressedVulnerabilitiesRow) *vulnerabilities.SuppressedVulnerability {
		state := vulnerabilities.SuppressState_NOT_SET
		switch row.Reason {
		case sql.VulnerabilitySuppressReasonFalsePositive:
			state = vulnerabilities.SuppressState_FALSE_POSITIVE
		case sql.VulnerabilitySuppressReasonResolved:

			state = vulnerabilities.SuppressState_RESOLVED
		case sql.VulnerabilitySuppressReasonNotAffected:
			state = vulnerabilities.SuppressState_NOT_AFFECTED
		case sql.VulnerabilitySuppressReasonInTriage:
			state = vulnerabilities.SuppressState_IN_TRIAGE
		}
		return &vulnerabilities.SuppressedVulnerability{
			ImageName:    row.ImageName,
			CveId:        row.CveID,
			Package:      row.Package,
			State:        state,
			Reason:       &row.ReasonText,
			SuppressedBy: &row.SuppressedBy,
			Suppress:     &row.Suppressed,
		}
	})

	return &vulnerabilities.ListSuppressedVulnerabilitiesResponse{
		Nodes:    nodes,
		PageInfo: pageInfo,
	}, nil
}

func (s *Server) GetVulnerabilityById(ctx context.Context, request *vulnerabilities.GetVulnerabilityByIdRequest) (*vulnerabilities.GetVulnerabilityByIdResponse, error) {
	uuId := convert.StringToUUID(request.Id)
	row, err := s.querier.GetVulnerabilityById(ctx, uuId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("vulnerability not found")
		}
		return nil, fmt.Errorf("get vulnerability by id: %w", err)
	}

	return &vulnerabilities.GetVulnerabilityByIdResponse{
		Vulnerability: &vulnerabilities.Vulnerability{
			Id:            row.ID.String(),
			Package:       row.Package,
			Suppression:   toSuppression(row.Suppressed, row.Reason.VulnerabilitySuppressReason, row.ReasonText, row.SuppressedBy, row.SuppressedAt.Time),
			LatestVersion: row.LatestVersion,
			ImageName:     row.ImageName,
			Cve: &vulnerabilities.Cve{
				Id:          row.CveID,
				Title:       row.CveTitle,
				Description: row.CveDesc,
				Link:        row.CveLink,
				Severity:    vulnerabilities.Severity(row.Severity),
				References:  row.Refs,
			},
		},
	}, nil
}

func (s *Server) ListWorkloadsForVulnerabilityById(ctx context.Context, request *vulnerabilities.ListWorkloadsForVulnerabilityByIdRequest) (*vulnerabilities.ListWorkloadsForVulnerabilityByIdResponse, error) {
	id := pgtype.UUID{
		Bytes: uuid.MustParse(request.Id),
		Valid: true,
	}

	row, err := s.querier.ListWorkloadsForVulnerabilityById(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("vulnerability not found")
		}
		return nil, fmt.Errorf("list workloads for vulnerability by id: %w", err)
	}

	workloads := collections.Map(row, func(r *sql.ListWorkloadsForVulnerabilityByIdRow) *vulnerabilities.Workload {
		return &vulnerabilities.Workload{
			Cluster:   r.Cluster,
			Namespace: r.Namespace,
			Name:      r.Name,
			Type:      r.WorkloadType,
			ImageName: r.ImageName,
			ImageTag:  r.ImageTag,
		}
	})
	return &vulnerabilities.ListWorkloadsForVulnerabilityByIdResponse{
		WorkloadRef: workloads,
	}, nil
}

func (s *Server) ListWorkloadsForVulnerability(ctx context.Context, request *vulnerabilities.ListWorkloadsForVulnerabilityRequest) (*vulnerabilities.ListWorkloadsForVulnerabilityResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}
	filter := request.GetFilter()
	if filter == nil {
		filter = &vulnerabilities.Filter{}
	}

	workloads, err := s.querier.ListWorkloadsForVulnerabilities(ctx, sql.ListWorkloadsForVulnerabilitiesParams{
		Cluster:                  filter.Cluster,
		Namespace:                filter.Namespace,
		WorkloadTypes:            filter.GetWorkloadTypes(),
		WorkloadName:             filter.Workload,
		CveIds:                   request.CveIds,
		CvssScore:                request.CvssScore,
		IncludeManagementCluster: request.IncludeManagementCluster,
		Offset:                   offset,
		Limit:                    limit,
		OrderBy:                  SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderByCritical),
	})
	if err != nil {
		return nil, fmt.Errorf("list workloads for vulnerability: %w", err)
	}

	total := 0
	nodes := collections.Map(workloads, func(row *sql.ListWorkloadsForVulnerabilitiesRow) *vulnerabilities.WorkloadForVulnerability {
		total = int(row.TotalCount)
		if row.WorkloadName == "flaky-frontend" {
			fmt.Println("debug")
		}
		return &vulnerabilities.WorkloadForVulnerability{
			WorkloadRef: &vulnerabilities.Workload{
				Cluster:   row.Cluster,
				Namespace: row.Namespace,
				Name:      row.WorkloadName,
				Type:      row.WorkloadType,
				ImageName: row.ImageName,
				ImageTag:  row.ImageTag,
			},
			Vulnerability: &vulnerabilities.Vulnerability{
				Id:      row.ID.String(),
				Package: row.Package,
				Suppression: toSuppression(
					row.Suppressed,
					row.Reason.VulnerabilitySuppressReason,
					row.ReasonText,
					row.SuppressedBy,
					row.SuppressedAt.Time,
				),
				CvssScore:     row.CvssScore,
				ImageName:     row.ImageName,
				Created:       timestamppb.New(row.CreatedAt.Time),
				LastUpdated:   timestamppb.New(row.UpdatedAt.Time),
				SeveritySince: timestamppb.New(row.SeveritySince.Time),
				LastSeverity:  &row.LastSeverity,
				Cve: &vulnerabilities.Cve{
					Id:          row.CveID,
					Title:       row.CveTitle,
					Description: row.CveDesc,
					Link:        row.CveLink,
					CvssScore:   row.CvssScore,
					Severity:    vulnerabilities.Severity(row.Severity),
					Created:     timestamppb.New(row.CveCreatedAt.Time),
					LastUpdated: timestamppb.New(row.CveUpdatedAt.Time),
				},
			},
		}
	})

	pageInfo, err := grpcpagination.PageInfo(request, total)
	if err != nil {
		return nil, err
	}
	response := &vulnerabilities.ListWorkloadsForVulnerabilityResponse{
		Nodes:    nodes,
		PageInfo: pageInfo,
	}
	return response, nil
}

func (s *Server) GetVulnerability(ctx context.Context, request *vulnerabilities.GetVulnerabilityRequest) (*vulnerabilities.GetVulnerabilityResponse, error) {
	row, err := s.querier.GetVulnerability(ctx, sql.GetVulnerabilityParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
		Package:   request.Package,
		CveID:     request.CveId,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("vulnerability not found")
		}
		return nil, fmt.Errorf("get vulnerability: %w", err)
	}

	return &vulnerabilities.GetVulnerabilityResponse{
		Vulnerability: &vulnerabilities.Vulnerability{
			Id:            row.ID.String(),
			Package:       row.Package,
			Suppression:   toSuppression(row.Suppressed, row.Reason.VulnerabilitySuppressReason, row.ReasonText, row.SuppressedBy, row.SuppressedAt.Time),
			LatestVersion: row.LatestVersion,
			Cve: &vulnerabilities.Cve{
				Id:          row.CveID,
				Title:       row.CveTitle,
				Description: row.CveDesc,
				Link:        row.CveLink,
				Severity:    vulnerabilities.Severity(row.Severity),
				References:  row.Refs,
			},
		},
	}, nil
}

func (s *Server) GetCve(ctx context.Context, request *vulnerabilities.GetCveRequest) (*vulnerabilities.GetCveResponse, error) {
	if err := validateInput(request.GetId()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid cve id: %v", err)
	}

	cve, err := s.querier.GetCve(ctx, request.Id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Errorf(codes.NotFound, "cve not found")
		}
		return nil, status.Errorf(codes.Internal, "get cve: %v", err)
	}

	cvssScore := 0.0
	if cve.CvssScore != nil {
		cvssScore = *cve.CvssScore
	}
	return &vulnerabilities.GetCveResponse{
		Cve: &vulnerabilities.Cve{
			Id:          cve.CveID,
			Title:       cve.CveTitle,
			Description: cve.CveDesc,
			Link:        cve.CveLink,
			Severity:    vulnerabilities.Severity(cve.Severity),
			References:  cve.Refs,
			Created:     timestamppb.New(cve.CreatedAt.Time),
			LastUpdated: timestamppb.New(cve.UpdatedAt.Time),
			CvssScore:   &cvssScore,
		},
	}, nil
}

func validateInput(s string) error {
	// only allow characters A-Z, a-z, 0-9, hyphen, underscore
	ok, err := regexp.Match(`^[A-Za-z0-9\-_]+$`, []byte(s))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("string contains invalid characters")
	}
	return nil
}

func (s *Server) SuppressVulnerability(ctx context.Context, request *vulnerabilities.SuppressVulnerabilityRequest) (*vulnerabilities.SuppressVulnerabilityResponse, error) {
	uuId := convert.StringToUUID(request.Id)
	vuln, err := s.querier.GetVulnerabilityById(ctx, uuId)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("get suppressed vulnerability: %w", err)
		}
	}

	supErr := s.querier.SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
		ImageName:    vuln.ImageName,
		CveID:        vuln.CveID,
		Package:      vuln.Package,
		SuppressedBy: request.GetSuppressedBy(),
		Suppressed:   request.GetSuppress(),
		Reason:       sql.VulnerabilitySuppressReason(strings.ToLower(request.GetState().String())),
		ReasonText:   request.GetReason(),
	})
	if supErr != nil {
		return nil, fmt.Errorf("suppress vulnerability: %w", supErr)
	}

	if err := s.querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: vuln.ImageName,
		ImageTag:  vuln.ImageTag,
	}); err != nil {
		return nil, fmt.Errorf("recalculate vulnerability summary: %w", err)
	}

	err = s.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		State: sql.ImageStateResync,
		Name:  vuln.ImageName,
		Tag:   vuln.ImageTag,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
	})
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.SuppressVulnerabilityResponse{
		CveId:      vuln.CveID,
		Suppressed: request.GetSuppress(),
	}, nil
}

// SanitizeOrderBy
// Special case: Severity is inverted (0 = Critical, 2 = Medium).
// Users expect "asc" = weakest → strongest, so we flip direction here
// to make SQL ordering intuitive.
func SanitizeOrderBy(orderBy *vulnerabilities.OrderBy, defaultOrder vulnerabilities.OrderByField) string {
	if orderBy == nil {
		orderBy = &vulnerabilities.OrderBy{
			Field:     string(defaultOrder),
			Direction: vulnerabilities.Direction_ASC,
		}
	}

	direction := "asc"
	if orderBy.Direction == vulnerabilities.Direction_DESC {
		direction = "desc"
	}

	field := vulnerabilities.OrderByField(strings.ToLower(orderBy.Field))
	if !field.IsValid() {
		field = defaultOrder
	}

	if field == vulnerabilities.OrderBySeverity || field == vulnerabilities.OrderByAffectedWorkloads {
		if direction == "asc" {
			direction = "desc"
		} else {
			direction = "asc"
		}
	}

	return fmt.Sprintf("%s_%s", field.String(), direction)
}

func safeInt(val *int32) int32 {
	if val == nil {
		return 0
	}
	return *val
}

func toSuppression(suppressed bool, suppressReason sql.VulnerabilitySuppressReason, reasonText *string, suppressedBy *string, suppressedAtTime time.Time) *vulnerabilities.Suppression {
	var suppression *vulnerabilities.Suppression
	if suppressReason.Valid() {
		suppressReasonStr := strings.ToUpper(string(suppressReason))
		t := suppressedAtTime

		reason := vulnerabilities.SuppressState_NOT_SET
		if val, ok := vulnerabilities.SuppressState_value[suppressReasonStr]; ok {
			reason = vulnerabilities.SuppressState(val)
		}

		suppression = &vulnerabilities.Suppression{
			SuppressedReason:  reason,
			SuppressedDetails: str(reasonText, ""),
			Suppressed:        suppressed,
			SuppressedBy:      str(suppressedBy, ""),
			LastUpdated:       timestamppb.New(t),
		}
	}
	return suppression
}

func str(s *string, def string) string {
	if s == nil {
		return def
	}
	return *s
}

func timestamptzFromProto(ts *timestamppb.Timestamp) pgtype.Timestamptz {
	if ts == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{
		Time:  ts.AsTime().UTC(),
		Valid: true,
	}
}

func toInt32Ptr(s *vulnerabilities.Severity) *int32 {
	if s == nil {
		return nil
	}
	v := int32(*s)
	return &v
}
