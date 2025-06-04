package grpcmgmt

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func (s *Server) TriggerSync(_ context.Context, _ *management.TriggerSyncRequest) (*management.TriggerSyncResponse, error) {
	go func() {
		err := s.updater.ResyncImages(s.parentCtx)
		if err != nil {
			s.log.WithError(err).Error("Failed to resync images")
		}
	}()

	return &management.TriggerSyncResponse{}, nil
}

func (s *Server) GetWorkloadStatus(ctx context.Context, request *management.GetWorkloadStatusRequest) (*management.GetWorkloadStatusResponse, error) {
	status, err := s.querier.ListWorkloadStatusWithJobs(ctx, sql.ListWorkloadStatusWithJobsParams{
		Cluster:       request.Cluster,
		Namespace:     request.Namespace,
		WorkloadName:  request.Workload,
		WorkloadTypes: []string{"app"},
	})
	if err != nil {
		s.log.WithError(err).Error("Failed to get workload status")
		return nil, err
	}

	workloads := groupWorkloadsWithJobs(status)
	return &management.GetWorkloadStatusResponse{
		WorkloadStatus: workloads,
	}, nil
}

func groupWorkloadsWithJobs(rows []*sql.ListWorkloadStatusWithJobsRow) []*management.WorkloadStatus {
	grouped := make(map[string]*management.WorkloadStatus)

	for _, row := range rows {
		key := fmt.Sprintf("%s|%s|%s|%s", row.WorkloadName, row.Namespace, row.Cluster, row.WorkloadType)

		if _, exists := grouped[key]; !exists {
			grouped[key] = &management.WorkloadStatus{
				Workload:          row.WorkloadName,
				WorkloadType:      row.WorkloadType,
				Namespace:         row.Namespace,
				Cluster:           row.Cluster,
				WorkloadState:     string(row.WorkloadState),
				WorkloadUpdatedAt: timestamppb.New(row.WorkloadUpdatedAt.Time),
				ImageName:         row.ImageName,
				ImageTag:          row.ImageTag,
				ImageState:        string(row.ImageState),
				ImageUpdatedAt:    timestamppb.New(row.ImageUpdatedAt.Time),
				Jobs:              []*management.Job{},
			}
		}

		// If there's a job on this row, add it
		if row.JobID != nil {

			grouped[key].Jobs = append(grouped[key].Jobs, &management.Job{
				Id:         *row.JobID,
				Kind:       *row.JobKind,
				State:      string(row.JobState.RiverJobState),
				Metadata:   row.JobMetadata,
				Attempts:   int32(*row.JobAttempt),
				Errors:     row.JobErrors,
				FinishedAt: timestamppb.New(row.JobFinalizedAt.Time),
			})
		}
	}

	// Flatten map to slice
	result := make([]*management.WorkloadStatus, 0, len(grouped))
	for _, workload := range grouped {
		result = append(result, workload)
	}

	return result
}
