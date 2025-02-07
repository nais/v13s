package grpcmgmt

import (
	"context"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	db        sql.Querier
	updater   *updater.Updater
	parentCtx context.Context
}

func NewServer(parentCtx context.Context, db sql.Querier, updater *updater.Updater) *Server {
	return &Server{
		parentCtx: parentCtx,
		db:        db,
		updater:   updater,
	}
}

// TODO: consider doing some of the updates async with go routines and return a response immediately
func (s *Server) RegisterWorkload(ctx context.Context, request *management.RegisterWorkloadRequest) (*management.RegisterWorkloadResponse, error) {
	metadata := map[string]string{}
	if request.Metadata != nil {
		metadata = request.Metadata.Labels
	}

	err := s.db.CreateImage(ctx, sql.CreateImageParams{
		Name:     request.ImageName,
		Tag:      request.ImageTag,
		Metadata: metadata,
	})

	if err != nil {
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

	err = s.db.UpsertWorkload(ctx, w)
	if err != nil {
		return nil, err
	}

	s.updater.QueueImage(s.parentCtx, request.ImageName, request.ImageTag)

	return &management.RegisterWorkloadResponse{}, nil
}
