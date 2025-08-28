package grpcmgmt

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/updater"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ management.ManagementServer = (*Server)(nil)

type Server struct {
	management.UnimplementedManagementServer
	querier   sql.Querier
	mgr       *manager.WorkloadManager
	updater   *updater.Updater
	parentCtx context.Context
	log       *logrus.Entry
}

func NewServer(parentCtx context.Context, pool *pgxpool.Pool, mgr *manager.WorkloadManager, updater *updater.Updater, field *logrus.Entry) *Server {
	return &Server{
		parentCtx: parentCtx,
		querier:   sql.New(pool),
		mgr:       mgr,
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

func (s *Server) GetWorkloadStatus(ctx context.Context, req *management.GetWorkloadStatusRequest) (*management.GetWorkloadStatusResponse, error) {
	rows, err := s.querier.ListWorkloadStatus(ctx, sql.ListWorkloadStatusParams{
		Cluster:       req.Cluster,
		Namespace:     req.Namespace,
		WorkloadName:  req.Workload,
		WorkloadTypes: []string{"app"},
		Limit:         req.Limit,
		Offset:        req.Offset,
	})
	if err != nil {
		s.log.WithError(err).Error("Failed to get workload status")
		return nil, err
	}

	total := 0
	if len(rows) > 0 {
		total = int(rows[0].Total)
	}

	hasNextPage := int(req.Offset)+int(req.Limit) < total
	hasPreviousPage := req.Offset > 0

	workloads := make([]*management.WorkloadStatus, 0, len(rows))
	for _, row := range rows {
		workloads = append(workloads, &management.WorkloadStatus{
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
			Jobs:              nil, // Not included here
		})
	}

	return &management.GetWorkloadStatusResponse{
		WorkloadStatus:  workloads,
		TotalCount:      int64(total),
		HasNextPage:     hasNextPage,
		HasPreviousPage: hasPreviousPage,
	}, nil
}

func (s *Server) GetWorkloadJobs(ctx context.Context, req *management.GetWorkloadJobsRequest) (*management.GetWorkloadJobsResponse, error) {
	rows, err := s.querier.ListJobsForWorkload(ctx, sql.ListJobsForWorkloadParams{
		WorkloadName: req.Workload,
		Namespace:    req.Namespace,
		Cluster:      req.Cluster,
		Offset:       req.Offset,
		Limit:        req.Limit,
	})
	if err != nil {
		s.log.WithError(err).Error("Failed to get workload jobs")
		return nil, err
	}

	jobs := make([]*management.Job, 0, len(rows))
	for _, row := range rows {
		var metadata, jobErrors string
		if row.JobMetadata != nil {
			metadata = row.JobMetadata.(string)
		}
		if row.JobErrors != nil {
			jobErrors = row.JobErrors.(string)
		}
		jobs = append(jobs, &management.Job{
			Id:         row.JobID,
			Kind:       row.JobKind,
			State:      string(row.JobState),
			Metadata:   metadata,
			Attempts:   int32(row.JobAttempt),
			Errors:     jobErrors,
			FinishedAt: timestamppb.New(row.JobFinalizedAt.Time),
		})
	}
	total := 0
	if len(rows) > 0 {
		total = int(rows[0].Total)
	}

	hasNextPage := int(req.Offset)+int(req.Limit) < total
	hasPreviousPage := req.Offset > 0

	return &management.GetWorkloadJobsResponse{
		Jobs:            jobs,
		TotalCount:      int64(total),
		HasNextPage:     hasNextPage,
		HasPreviousPage: hasPreviousPage,
	}, nil
}

func (s *Server) Resync(ctx context.Context, request *management.ResyncRequest) (*management.ResyncResponse, error) {
	workloadState := sql.WorkloadStateUpdated
	if request.WorkloadState != nil {
		workloadState = sql.WorkloadState(*request.WorkloadState)
	}
	rows, err := s.querier.SetWorkloadState(ctx, sql.SetWorkloadStateParams{
		Cluster:      request.Cluster,
		Namespace:    request.Namespace,
		WorkloadName: request.Workload,
		WorkloadType: request.WorkloadType,
		OldState:     workloadState,
		State:        sql.WorkloadStateResync,
	})
	if err != nil {
		s.log.WithError(err).Error("failed to set workload state")
		return nil, err
	}
	workloads := make([]string, 0)
	for _, row := range rows {
		workload := &model.Workload{
			Cluster:   row.Cluster,
			Namespace: row.Namespace,
			Name:      row.Name,
			Type:      model.WorkloadType(row.WorkloadType),
			ImageName: row.ImageName,
			ImageTag:  row.ImageTag,
		}

		err = s.mgr.AddWorkload(ctx, workload)
		if err != nil {
			s.log.WithError(err).Error("failed to add workload to job queue")
			return nil, err
		}

		imageState := sql.ImageStateResync
		if request.ImageState != nil {
			imageState = sql.ImageState(*request.ImageState)
		}

		err = s.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
			State: imageState,
			Name:  workload.ImageName,
			Tag:   workload.ImageTag,
			ReadyForResyncAt: pgtype.Timestamptz{
				Time:  time.Now(),
				Valid: true,
			},
		})
		if err != nil {
			return nil, err
		}

		workloads = append(workloads,
			fmt.Sprintf("%s/%s/%s/%s", workload.Cluster, workload.Namespace, workload.Type, workload.Name))
	}

	if len(workloads) == 0 {
		s.log.Debugf("no workloads to resync")
		return &management.ResyncResponse{}, nil
	}

	go func() {
		err = s.updater.ResyncImageVulnerabilities(s.parentCtx)
		if err != nil {
			fmt.Printf("failed to resync images: %v\n", err)
		}
	}()

	return &management.ResyncResponse{
		NumWorkloads: int32(len(workloads)),
		Workloads:    workloads,
	}, nil
}
