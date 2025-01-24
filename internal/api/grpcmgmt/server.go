package grpcmgmt

import (
	"context"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dependencytrack"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	DpClient *dependencytrack.Client
	Db       *sql.Queries
}

func (s *Server) CreateWorkload(ctx context.Context, request *management.CreateWorkloadRequest) (*management.CreateWorkloadResponse, error) {
	metadata := map[string]string{}
	if request.Metadata != nil {
		metadata = request.Metadata.Labels
	}

	imageParams := sql.CreateImageParams{
		Name:     request.ImageName,
		Tag:      request.ImageTag,
		Metadata: metadata,
	}

	_, err := s.Db.CreateImage(ctx, imageParams)
	if err != nil {
		return nil, err
	}

	w := sql.CreateWorkloadParams{
		Name:         request.Workload,
		WorkloadType: request.WorkloadType,
		Namespace:    request.Namespace,
		Cluster:      request.Cluster,
		ImageName:    request.ImageName,
		ImageTag:     request.ImageTag,
	}

	_, err = s.Db.CreateWorkload(ctx, w)
	if err != nil {
		return nil, err
	}

	p, err := s.DpClient.GetProject(ctx, request.ImageName, request.ImageTag)
	if err != nil {
		return nil, err
	}

	response := &management.CreateWorkloadResponse{}
	if p.Metrics == nil {
		return response, nil
	}

	summary := sql.UpsertVulnerabilitySummaryParams{
		ImageName: request.ImageName,
		ImageTag:  request.ImageTag,
		Critical:  p.Metrics.Critical,
		High:      p.Metrics.High,
		Medium:    p.Metrics.Medium,
		Low:       p.Metrics.Low,
	}

	if p.Metrics.Unassigned != nil {
		summary.Unassigned = *p.Metrics.Unassigned
	}

	if p.Metrics.InheritedRiskScore != nil {
		summary.RiskScore = int32(*p.Metrics.InheritedRiskScore)
	}

	err = s.Db.UpsertVulnerabilitySummary(ctx, summary)

	return response, err
}

func (s *Server) UpdateWorkload(ctx context.Context, request *management.UpdateWorkloadRequest) (*management.UpdateWorkloadResponse, error) {
	//TODO implement me
	panic("implement me")
}
