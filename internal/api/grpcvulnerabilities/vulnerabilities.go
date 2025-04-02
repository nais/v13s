package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/emicklei/pgtalk/convert"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/nais/v13s/internal/api/grpcpagination"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
)

// TODO: add input validation for request, especially for filter values
func (s *Server) ListVulnerabilities(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesRequest) (*vulnerabilities.ListVulnerabilitiesResponse, error) {
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
		OrderBy:           sanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
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
		OrderBy:           sanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities for image: %w", err)
	}

	total, err := s.querier.CountVulnerabilitiesForImage(ctx, sql.CountVulnerabilitiesForImageParams{
		ImageName:         request.GetImageName(),
		ImageTag:          request.GetImageTag(),
		IncludeSuppressed: &request.IncludeSuppressed,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities for image: %w", err)
	}

	pageInfo, err := grpcpagination.PageInfo(request, int(total))
	if err != nil {
		return nil, err
	}

	nodes := collections.Map(vulnz, func(row *sql.ListVulnerabilitiesForImageRow) *vulnerabilities.Vulnerability {

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
			LatestVersion: row.LatestVersion,
			Cve: &vulnerabilities.Cve{
				Id:          row.CveID,
				Title:       row.CveTitle,
				Description: row.CveDesc,
				Link:        row.CveLink,
				Severity:    vulnerabilities.Severity(row.Severity),
				References:  row.Refs,
			},
		}
	})

	return &vulnerabilities.ListVulnerabilitiesForImageResponse{
		Nodes:    nodes,
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
		OrderBy:   sanitizeOrderBy(request.OrderBy, vulnerabilities.OrderBySeverity),
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
		return &vulnerabilities.SuppressedVulnerability{
			ImageName:    row.ImageName,
			CveId:        row.CveID,
			Package:      row.Package,
			State:        suppressState(row.Reason),
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
	uuid := convert.StringToUUID(request.Id)
	row, err := s.querier.GetVulnerabilityById(ctx, uuid)
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

func (s *Server) SuppressVulnerability(ctx context.Context, request *vulnerabilities.SuppressVulnerabilityRequest) (*vulnerabilities.SuppressVulnerabilityResponse, error) {
	uuid := convert.StringToUUID(request.Id)
	vuln, err := s.querier.GetVulnerabilityById(ctx, uuid)
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

	return &vulnerabilities.SuppressVulnerabilityResponse{
		CveId:      vuln.CveID,
		Suppressed: request.GetSuppress(),
	}, nil
}

func sanitizeOrderBy(orderBy *vulnerabilities.OrderBy, defaultOrder vulnerabilities.OrderByField) string {
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

	return fmt.Sprintf("%s_%s", field.String(), direction)
}

func safeInt(val *int32) int32 {
	if val == nil {
		return 0
	}
	return *val
}

func toSuppression(suppressed bool, suppressReason sql.VulnerabilitySuppressReason, reasonText *string, suppressedBy *string, suppressedAt time.Time) *vulnerabilities.Suppression {
	var suppression *vulnerabilities.Suppression
	if suppressReason.Valid() {
		suppressReasonStr := strings.ToUpper(string(suppressReason))
		time := suppressedAt

		reason := vulnerabilities.SuppressState_NOT_SET
		if val, ok := vulnerabilities.SuppressState_value[suppressReasonStr]; ok {
			reason = vulnerabilities.SuppressState(val)
		}

		suppression = &vulnerabilities.Suppression{
			SuppressedReason:  reason,
			SuppressedDetails: str(reasonText, ""),
			Suppressed:        suppressed,
			SuppressedBy:      str(suppressedBy, ""),
			LastUpdated:       timestamppb.New(time),
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

func suppressState(state sql.VulnerabilitySuppressReason) vulnerabilities.SuppressState {
	switch state {
	case sql.VulnerabilitySuppressReasonFalsePositive:
		return vulnerabilities.SuppressState_FALSE_POSITIVE
	case sql.VulnerabilitySuppressReasonResolved:
		return vulnerabilities.SuppressState_RESOLVED
	case sql.VulnerabilitySuppressReasonNotAffected:
		return vulnerabilities.SuppressState_NOT_AFFECTED
	case sql.VulnerabilitySuppressReasonInTriage:
		return vulnerabilities.SuppressState_IN_TRIAGE
	default:
		return vulnerabilities.SuppressState_NOT_SET
	}
}
