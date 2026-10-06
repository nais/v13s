package grpcvulnerabilities

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

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
		RiskTiers:         priorityTiersFromPriorities(request.GetPriorities()),
		HasKev:            request.HasKev,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities for image: %w", err)
	}

	total := 0
	nodes := collections.Map(vulnz, func(row *sql.ListVulnerabilitiesForImageRow) *vulnerabilities.Vulnerability {
		total = int(row.TotalCount)
		return defaultVulnerabilityProjector.ToVulnerabilityFromListVulnerabilitiesForImageRow(row)
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
		Vulnerability: defaultVulnerabilityProjector.ToVulnerabilityFromGetVulnerabilityByIDRow(row),
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

	excludeNamespaces := request.GetExcludeNamespaces()
	if excludeNamespaces == nil {
		excludeNamespaces = []string{}
	}

	excludeClusters := request.GetExcludeClusters()
	if excludeClusters == nil {
		excludeClusters = []string{}
	}

	cveIDs := request.CveIds
	if len(cveIDs) > 0 {
		cveIDs, err = s.resolveCanonicalCveIDs(ctx, cveIDs)
		if err != nil {
			return nil, err
		}
	}

	namespaces := filter.GetNamespaces()
	if ns := filter.GetNamespace(); ns != "" {
		namespaces = append(namespaces, ns)
	}
	if namespaces == nil {
		namespaces = []string{}
	}

	workloads, err := s.querier.ListWorkloadsForVulnerabilities(ctx, sql.ListWorkloadsForVulnerabilitiesParams{
		Cluster:           filter.Cluster,
		Namespaces:        namespaces,
		WorkloadTypes:     filter.GetWorkloadTypes(),
		WorkloadName:      filter.Workload,
		CveIds:            cveIDs,
		CvssScore:         request.CvssScore,
		ExcludeClusters:   excludeClusters,
		ExcludeNamespaces: excludeNamespaces,
		IncludeSuppressed: request.IncludeSuppressed,
		Offset:            offset,
		Limit:             limit,
		OrderBy:           SanitizeOrderBy(request.OrderBy, vulnerabilities.OrderByCritical),
	})
	if err != nil {
		return nil, fmt.Errorf("list workloads for vulnerability: %w", err)
	}

	total := 0
	nodes := collections.Map(workloads, func(row *sql.ListWorkloadsForVulnerabilitiesRow) *vulnerabilities.WorkloadForVulnerability {
		total = int(row.TotalCount)
		return defaultVulnerabilityProjector.ToWorkloadForVulnerability(row)
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

	return &vulnerabilities.GetCveResponse{
		Cve: toCve(cvePayload{
			id:                 cve.CveID,
			title:              cve.CveTitle,
			desc:               cve.CveDesc,
			link:               cve.CveLink,
			severity:           cve.Severity,
			refs:               cve.Refs,
			created:            timestamppb.New(cve.CreatedAt.Time),
			lastUpdated:        timestamppb.New(cve.UpdatedAt.Time),
			cvssScore:          cve.CvssScore,
			epssScore:          cve.EpssScore,
			epssPercentile:     cve.EpssPercentile,
			hasKevEntry:        cve.HasKevEntry,
			knownRansomwareUse: cve.KnownRansomwareUse,
			priority:           cve.Priority,
		}),
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
	workflow := newSuppressionWorkflow(s.querier, s.resolveCanonicalCveIDs)
	result, err := workflow.SuppressOne(ctx, suppressOneInput{
		id:           convert.StringToUUID(request.Id),
		suppressedBy: request.GetSuppressedBy(),
		suppress:     request.GetSuppress(),
		reason:       sql.VulnerabilitySuppressReason(strings.ToLower(request.GetState().String())),
		reasonText:   request.GetReason(),
	})
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.SuppressVulnerabilityResponse{
		CveId:      result.cveID,
		Suppressed: result.suppressed,
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

	if field == vulnerabilities.OrderBySeverity || field == vulnerabilities.OrderByTopPriority {
		if direction == "asc" {
			direction = "desc"
		} else {
			direction = "asc"
		}
	}

	if field == vulnerabilities.OrderByTopPriority {
		return fmt.Sprintf("%s_%s", "top_risk_tier", direction)
	}

	return fmt.Sprintf("%s_%s", field.String(), direction)
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
	return new(int32(*s))
}
