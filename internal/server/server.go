package server

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/internal/dependencytrack/client"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"log"
	"strings"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
	DpClient *dependencytrack.Client
}

func (s *Server) getFilteredProjects(ctx context.Context, filter *vulnerabilities.Filter) ([]client.Project, error) {
	if filter == nil {
		return s.DpClient.GetProjects(ctx)
	}

	if filter.Cluster != nil && filter.Namespace != nil {
		tagFilter := "team:" + *filter.Namespace
		return s.DpClient.GetProjectsByTag(ctx, tagFilter)
	} else if filter.Cluster != nil {
		tagFilter := "env:" + *filter.Cluster
		return s.DpClient.GetProjectsByTag(ctx, tagFilter)
	} else if filter.Namespace != nil {
		fmt.Println("filter.Namespace: ", *filter.Namespace)
		tagFilter := "team:" + *filter.Namespace
		return s.DpClient.GetProjectsByTag(ctx, tagFilter)
	}

	// Fetch all projects if no specific cluster or namespace is defined
	return s.DpClient.GetProjects(ctx)
}

func (s *Server) parseSummariesFrom(projects []client.Project) []*vulnerabilities.WorkloadSummary {
	var summaries []*vulnerabilities.WorkloadSummary

	for _, project := range projects {
		for _, tag := range project.Tags {
			if tag.Name == nil || !strings.HasPrefix(*tag.Name, "workload:") {
				continue
			}

			parts := strings.Split(strings.TrimPrefix(*tag.Name, "workload:"), "|")
			if len(parts) != 4 {
				log.Printf("Invalid workload tag: %s", *tag.Name)
				continue
			}

			summary := &vulnerabilities.WorkloadSummary{
				Workload: workload(parts[0], parts[1], parts[3], parts[2], *project.Name),
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

// ListVulnerabilitySummaries implements the ListVulnerabilitySummaries RPC
func (s *Server) ListVulnerabilitySummaries(ctx context.Context, req *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	log.Printf("Received ListVulnerabilitySummaries request: %v", req)

	projects, err := s.getFilteredProjects(ctx, req.Filter)
	if err != nil {
		return nil, err
	}

	allSummaries := s.parseSummariesFrom(projects)
	filteredSummaries := allSummaries

	// Apply further filtering if necessary (for Workload and WorkloadType)
	if req.Filter != nil && (req.Filter.Workload != nil || req.Filter.WorkloadType != nil) {
		filteredSummaries = collections.Filter(allSummaries, func(summary *vulnerabilities.WorkloadSummary) bool {
			return matchesFilter(summary.Workload, req.Filter)
		})
	}

	response := &vulnerabilities.ListVulnerabilitySummariesResponse{
		WorkloadSummaries: filteredSummaries,
	}
	log.Printf("Responding with: %v", response)
	return response, nil
}

func (s *Server) ListVulnerabilities(ctx context.Context, request *vulnerabilities.ListVulnerabilitiesRequest) (*vulnerabilities.ListVulnerabilitiesResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetVulnerabilitySummary(ctx context.Context, request *vulnerabilities.GetVulnerabilitySummaryRequest) (*vulnerabilities.GetVulnerabilitySummaryResponse, error) {
	//TODO implement me
	panic("implement me")
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