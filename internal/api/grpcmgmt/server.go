package grpcmgmt

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
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

func (s *Server) RegisterWorkload(ctx context.Context, request *management.RegisterWorkloadRequest) (*management.RegisterWorkloadResponse, error) {
	metadata := map[string]string{}
	if request.Metadata != nil {
		metadata = request.Metadata.Labels
	}

	_, err := s.Db.GetImage(ctx, sql.GetImageParams{
		Name: request.ImageName,
		Tag:  request.ImageTag,
	})

	if errors.Is(err, pgx.ErrNoRows) {
		_, err = s.Db.CreateImage(ctx, sql.CreateImageParams{
			Name:     request.ImageName,
			Tag:      request.ImageTag,
			Metadata: metadata,
		})
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	w := sql.UpsertWorkloadParams{
		Name:         request.Workload,
		WorkloadType: request.WorkloadType,
		Namespace:    request.Namespace,
		Cluster:      request.Cluster,
		ImageName:    request.ImageName,
		ImageTag:     request.ImageTag,
	}

	err = s.Db.UpsertWorkload(ctx, w)
	if err != nil {
		return nil, err
	}

	p, err := s.DpClient.GetProject(ctx, request.ImageName, request.ImageTag)
	if err != nil {
		return nil, err
	}

	response := &management.RegisterWorkloadResponse{}
	if p == nil || p.Metrics == nil {
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
