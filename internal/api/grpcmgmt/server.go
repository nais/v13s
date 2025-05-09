package grpcmgmt

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	querier   sql.Querier
	updater   *updater.Updater
	parentCtx context.Context
	log       *logrus.Entry
}

func (s *Server) TriggerSync(_ context.Context, _ *management.TriggerSyncRequest) (*management.TriggerSyncResponse, error) {
	go func() {
		err := s.updater.ResyncImages(s.parentCtx)
		if err != nil {
			s.log.WithError(err).Error("Failed to resync images")
		}
	}()

	return &management.TriggerSyncResponse{}, nil
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

	if err := s.querier.CreateImage(ctx, sql.CreateImageParams{
		Name:     request.ImageName,
		Tag:      request.ImageTag,
		Metadata: metadata,
	}); err != nil {
		s.log.WithError(err).Error("Failed to create image")
		return nil, err
	}

	isPlatformImage := collections.AnyMatch([]string{
		"gcr.io/cloud-sql-connectors/cloud-sql-proxy",
		"docker.io/devopsfaith/krakend",
		"europe-north1-docker.pkg.dev/nais-io/nais/images/elector",
	}, func(e string) bool {
		return e == request.ImageName || request.Workload == "wonderwall"
	})

	wType := request.WorkloadType
	if isPlatformImage {
		wType = "platform"
	}

	if _, err := s.querier.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         request.Workload,
		WorkloadType: wType,
		Namespace:    request.Namespace,
		Cluster:      request.Cluster,
		ImageName:    request.ImageName,
		ImageTag:     request.ImageTag,
	}); err != nil {
		s.log.WithError(err).Error("Failed to upsert workload")
		return nil, err
	}

	// TODO: we need to do something here, it gets invoked a lot of times within a short period of time
	// have some checks if image needs updating.. maybe just set state initialized and let the updater handle it
	// need something so that new images get updated almost at once

	//s.updater.QueueImage(s.parentCtx, request.ImageName, request.ImageTag)

	return &management.RegisterWorkloadResponse{}, nil
}
