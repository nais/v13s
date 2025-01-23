package server

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/database/sql"
	"log"
	"strings"
	"time"

	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/internal/grpc/grpcpagination"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	DpClient *dependencytrack.Client
	Db       *sql.Queries
}

func (s *Server) ListVulnerabilitySummaries(ctx context.Context, req *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(req)
	if err != nil {
		return nil, err
	}

	summaries, err := s.Db.ListVulnerabilitySummaries(ctx, sql.ListVulnerabilitySummariesParams{
		Cluster:      req.Filter.Cluster,
		Namespace:    req.Filter.Namespace,
		WorkloadType: req.Filter.WorkloadType,
		WorkloadName: req.Filter.Workload,
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
				Unknown:     0,
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

	pageInfo, err := grpcpagination.PageInfo(req, len(ws))
	if err != nil {
		return nil, err
	}

	response := &vulnerabilities.ListVulnerabilitySummariesResponse{
		WorkloadSummaries: ws,
		PageInfo:          pageInfo,
	}
	return response, nil
}

func (s *Server) getFilteredProjects(ctx context.Context, filter *vulnerabilities.Filter, limit int32, offset int32) ([]client.Project, error) {
	if filter == nil {
		return s.DpClient.GetProjects(ctx, limit, offset)
	}

	if filter.Cluster != nil && filter.Namespace != nil {
		tagFilter := "team:" + *filter.Namespace
		return s.DpClient.GetProjectsByTag(ctx, tagFilter, limit, offset)
	} else if filter.Cluster != nil {
		tagFilter := "env:" + *filter.Cluster
		return s.DpClient.GetProjectsByTag(ctx, tagFilter, limit, offset)
	} else if filter.Namespace != nil {
		tagFilter := "team:" + *filter.Namespace
		return s.DpClient.GetProjectsByTag(ctx, tagFilter, limit, offset)
	}

	// Fetch all projects if no specific cluster or namespace is defined
	return s.DpClient.GetProjects(ctx, limit, offset)
}

func (s *Server) parseSummariesFrom(projects []client.Project) []*vulnerabilities.WorkloadSummary {
	var summaries []*vulnerabilities.WorkloadSummary

	for _, project := range projects {
		workloads := s.extractWorkloadsFromProject(project)

		for _, w := range workloads {
			summary := &vulnerabilities.WorkloadSummary{
				Workload: w,
			}

			if project.Metrics != nil {
				summary.VulnerabilitySummary = metric(
					project.Metrics.Critical,
					project.Metrics.High,
					project.Metrics.Medium,
					project.Metrics.Low,
					*project.Metrics.Unassigned,
				)
			}

			summaries = append(summaries, summary)
		}
	}

	return summaries
}

func (s *Server) getFilteredSummaries(projects []client.Project, filter *vulnerabilities.Filter) ([]*vulnerabilities.WorkloadSummary, error) {
	allSummaries := s.parseSummariesFrom(projects)
	filteredSummaries := allSummaries

	// Apply additional filtering for Workload and WorkloadType
	if filter != nil && (filter.Workload != nil || filter.WorkloadType != nil) {
		filteredSummaries = collections.Filter(allSummaries, func(summary *vulnerabilities.WorkloadSummary) bool {
			return matchesFilter(summary.Workload, filter)
		})
	}

	return filteredSummaries, nil
}

func (s *Server) extractWorkloadsFromProject(project client.Project) []*vulnerabilities.Workload {
	var workloads []*vulnerabilities.Workload

	for _, tag := range project.Tags {
		if tag.Name == nil || !strings.HasPrefix(*tag.Name, "workload:") {
			continue
		}

		parts := strings.Split(strings.TrimPrefix(*tag.Name, "workload:"), "|")
		if len(parts) != 4 {
			log.Printf("Invalid workload tag: %s", *tag.Name)
			continue
		}

		workloads = append(workloads, workload(parts[0], parts[1], parts[3], parts[2], *project.Name))
	}

	return workloads
}

func (s *Server) filterWorkloads(workloads []*vulnerabilities.Workload, filter *vulnerabilities.Filter) []*vulnerabilities.Workload {
	if filter == nil || (filter.Workload == nil && filter.WorkloadType == nil) {
		return workloads
	}
	return collections.Filter(workloads, func(workload *vulnerabilities.Workload) bool {
		return matchesFilter(workload, filter)
	})
}

func (s *Server) getVulnerabilitiesForWorkload(ctx context.Context, project client.Project, workload *vulnerabilities.Workload, includeSuppressed bool) (*vulnerabilities.WorkloadVulnerabilities, error) {
	findings, err := s.getFindings(ctx, project, includeSuppressed)
	if err != nil {
		return nil, err
	}

	var vuln []*vulnerabilities.Vulnerability
	for _, finding := range findings {
		vulnerability, err := s.parseFindingToVulnerability(finding)
		if err != nil {
			return nil, err
		}
		vuln = append(vuln, vulnerability)
	}

	return &vulnerabilities.WorkloadVulnerabilities{
		Workload:        workload,
		Vulnerabilities: vuln,
		LastUpdated:     timestamppb.New(time.Now()),
	}, nil
}

func (s *Server) processProjects(ctx context.Context, projects []client.Project, request *vulnerabilities.ListVulnerabilitiesRequest) ([]*vulnerabilities.WorkloadVulnerabilities, error) {
	var workloadVulnerabilities []*vulnerabilities.WorkloadVulnerabilities

	for _, project := range projects {
		workloads := s.extractWorkloadsFromProject(project)
		filteredWorkloads := s.filterWorkloads(workloads, request.Filter)

		for _, w := range filteredWorkloads {
			vuln, err := s.getVulnerabilitiesForWorkload(ctx, project, w, request.GetSuppressed())
			if err != nil {
				return nil, err
			}
			workloadVulnerabilities = append(workloadVulnerabilities, vuln)
		}
	}

	return workloadVulnerabilities, nil
}

func (s *Server) ListVulnerabilities(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesRequest) (*vulnerabilities.ListVulnerabilitiesResponse, error) {
	limit, offset, err := grpcpagination.Pagination(request)
	if err != nil {
		return nil, err
	}

	projects, err := s.getFilteredProjects(ctx, request.Filter, limit, offset)
	if err != nil {
		return nil, err
	}

	workloadVulnerabilities, err := s.processProjects(ctx, projects, request)
	if err != nil {
		return nil, err
	}

	pageInfo, err := grpcpagination.PageInfo(request, len(workloadVulnerabilities))
	if err != nil {
		return nil, err
	}

	return &vulnerabilities.ListVulnerabilitiesResponse{
		Filter:    request.Filter,
		Workloads: workloadVulnerabilities,
		PageInfo:  pageInfo,
	}, nil
}

func (s *Server) parseFindingToVulnerability(finding client.Finding) (*vulnerabilities.Vulnerability, error) {
	component, componentOk := finding.GetComponentOk()
	if !componentOk {
		return nil, fmt.Errorf("missing component for finding")
	}

	analysis, analysisOk := finding.GetAnalysisOk()
	if !analysisOk {
		return nil, fmt.Errorf("missing analysis for finding")
	}

	vulnData, vulnOk := finding.GetVulnerabilityOk()
	if !vulnOk {
		return nil, fmt.Errorf("missing vulnerability data for finding")
	}

	var severity vulnerabilities.Severity
	switch vulnData["severity"].(string) {
	case "CRITICAL":
		severity = vulnerabilities.Severity_CRITICAL
	case "HIGH":
		severity = vulnerabilities.Severity_HIGH
	case "MEDIUM":
		severity = vulnerabilities.Severity_MEDIUM
	case "LOW":
		severity = vulnerabilities.Severity_LOW
	default:
		severity = vulnerabilities.Severity_UNASSIGNED
	}

	var link string
	switch vulnData["source"].(string) {
	case "NVD":
		link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vulnData["vulnId"].(string))
	case "GITHUB":
		link = fmt.Sprintf("https://github.com/advisories/%s", vulnData["vulnId"].(string))
	}

	isSuppressed := analysis["isSuppressed"].(bool)
	return &vulnerabilities.Vulnerability{
		Package: component["purl"].(string),
		Cwe: &vulnerabilities.Cwe{
			Id:          vulnData["vulnId"].(string),
			Title:       vulnData["title"].(string),
			Description: vulnData["description"].(string),
			Link:        link,
			Severity:    severity,
		},
		Suppressed: &isSuppressed,
	}, nil
}

func (s *Server) getFindings(ctx context.Context, project client.Project, suppressed bool) ([]client.Finding, error) {
	projectFindings, err := s.DpClient.GetFindings(ctx, project.Uuid, suppressed)
	if err != nil {
		return nil, err
	}
	return projectFindings, nil
}

func (s *Server) GetVulnerabilitySummary(ctx context.Context, req *vulnerabilities.GetVulnerabilitySummaryRequest) (*vulnerabilities.GetVulnerabilitySummaryResponse, error) {
	limit, offset, err := grpcpagination.Pagination(req)
	if err != nil {
		return nil, err
	}

	projects, err := s.getFilteredProjects(ctx, req.Filter, limit, offset)
	if err != nil {
		return nil, err
	}

	filteredSummaries, err := s.getFilteredSummaries(projects, req.Filter)
	if err != nil {
		return nil, err
	}

	now := time.Now().Truncate(24 * time.Hour)
	lastUpdated := timestamppb.New(now)
	summary := vulnerabilities.Summary{
		LastUpdated: lastUpdated,
	}

	for _, sum := range filteredSummaries {
		if sum.VulnerabilitySummary != nil {
			summary.Critical += sum.VulnerabilitySummary.Critical
			summary.High += sum.VulnerabilitySummary.High
			summary.Medium += sum.VulnerabilitySummary.Medium
			summary.Low += sum.VulnerabilitySummary.Low
			summary.Unassigned += sum.VulnerabilitySummary.Unassigned
		}
	}

	pageInfo, err := grpcpagination.PageInfo(req, 1)
	if err != nil {
		return nil, err
	}

	response := &vulnerabilities.GetVulnerabilitySummaryResponse{
		Filter:               req.Filter,
		VulnerabilitySummary: &summary,
		PageInfo:             pageInfo,
	}
	return response, nil
}

func matchesFilter(workload *vulnerabilities.Workload, filter *vulnerabilities.Filter) bool {
	if filter == nil {
		return true
	}
	if filter.Cluster != nil && workload.Cluster != *filter.Cluster {
		return false
	}
	if filter.Namespace != nil && workload.Namespace != *filter.Namespace {
		return false
	}
	if filter.Workload != nil && workload.Name != *filter.Workload {
		return false
	}
	if filter.WorkloadType != nil && workload.Type != *filter.WorkloadType {
		return false
	}
	return true
}

func workload(c, ns, n, t, i string) *vulnerabilities.Workload {
	return &vulnerabilities.Workload{
		Cluster:   c,
		Namespace: ns,
		Name:      n,
		Type:      t,
		Image:     i,
	}
}

func metric(c, h, m, l, u int32) *vulnerabilities.Summary {
	return &vulnerabilities.Summary{
		Critical:   c,
		High:       h,
		Medium:     m,
		Low:        l,
		Unassigned: u,
	}
}
