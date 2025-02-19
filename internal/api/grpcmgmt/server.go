package grpcmgmt

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	querier   sql.Querier
	updater   *updater.Updater
	parentCtx context.Context
	log       *logrus.Entry
}

func NewServer(parentCtx context.Context, pool *pgxpool.Pool, updater *updater.Updater, field *logrus.Entry) *Server {
	return &Server{
		parentCtx: parentCtx,
		querier:   sql.New(pool),
		updater:   updater,
		log:       field,
	}
}

func (s *Server) RegisterWorkload(ctx context.Context, request *management.RegisterWorkloadRequest) (*management.RegisterWorkloadResponse, error) {
	metadata := map[string]string{}
	if request.Metadata != nil {
		metadata = request.Metadata.Labels
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return s.querier.CreateImage(ctx, sql.CreateImageParams{
			Name:     request.ImageName,
			Tag:      request.ImageTag,
			Metadata: metadata,
		})
	})

	g.Go(func() error {
		return s.querier.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name:         request.Workload,
			WorkloadType: request.WorkloadType,
			Namespace:    request.Namespace,
			Cluster:      request.Cluster,
			ImageName:    request.ImageName,
			ImageTag:     request.ImageTag,
		})
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	s.updater.QueueImage(s.parentCtx, request.ImageName, request.ImageTag)

	return &management.RegisterWorkloadResponse{}, nil
}
