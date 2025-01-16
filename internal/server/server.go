package server

import (
	"context"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"log"
)

var _ vulnerabilities.VulnerabilitiesServer = (*Server)(nil)

type Server struct {
	vulnerabilities.UnimplementedVulnerabilitiesServer
}

// ListVulnerabilitySummaries implements the ListVulnerabilitySummaries RPC
func (s *Server) ListVulnerabilitySummaries(ctx context.Context, req *vulnerabilities.ListVulnerabilitySummariesRequest) (*vulnerabilities.ListVulnerabilitySummariesResponse, error) {
	log.Printf("Received ListVulnerabilitySummaries request: %v", req)

	allSummaries := summaries()
	filteredSummaries := make([]*vulnerabilities.WorkloadSummary, 0)
	if req.Filter != nil {
		filteredSummaries = collections.Filter(allSummaries, func(summary *vulnerabilities.WorkloadSummary) bool {
			return matchesFilter(summary.Workload, req.Filter)
		})
	} else {
		filteredSummaries = allSummaries
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

func summaries() []*vulnerabilities.WorkloadSummary {
	return []*vulnerabilities.WorkloadSummary{
		{
			Workload:             workload("cluster-1", "namespace-1", "workload-1", "deployment", "image-1"),
			VulnerabilitySummary: &vulnerabilities.Summary{Critical: 5, High: 10, Medium: 20, Low: 15},
		},
		{
			Workload:             workload("cluster-1", "namespace-1", "workload-2", "deployment", "image-2"),
			VulnerabilitySummary: &vulnerabilities.Summary{Critical: 5, High: 10, Medium: 20, Low: 15},
		},
		{
			Workload:             workload("cluster-1", "namespace-2", "workload-3", "deployment", "image-3"),
			VulnerabilitySummary: &vulnerabilities.Summary{Critical: 5, High: 10, Medium: 20, Low: 15},
		},
	}
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
