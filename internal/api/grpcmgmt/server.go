package grpcmgmt

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/resync"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ management.ManagementServer = (*Server)(nil)

type workloadManager interface {
	AddWorkload(ctx context.Context, workload *model.Workload) error
	DeleteWorkload(ctx context.Context, workload *model.Workload) error
}

type Server struct {
	management.UnimplementedManagementServer
	querier sql.Querier
	mgr     workloadManager
	resync  resync.Module
	log     *logrus.Entry
}

func NewServer(pool *pgxpool.Pool, mgr workloadManager, resyncModule resync.Module, field *logrus.Entry) *Server {
	return &Server{
		querier: sql.New(pool),
		mgr:     mgr,
		resync:  resyncModule,
		log:     field,
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

	// s.updater.QueueImage(s.parentCtx, request.ImageName, request.ImageTag)

	return &management.RegisterWorkloadResponse{}, nil
}

func (s *Server) GetWorkloadStatus(ctx context.Context, req *management.GetWorkloadStatusRequest) (*management.GetWorkloadStatusResponse, error) {
	workloadType := "app"
	if req.WorkloadType != nil {
		workloadType = *req.WorkloadType
	}

	if req.Limit == 0 {
		req.Limit = 30
	}

	rows, err := s.querier.ListWorkloadStatus(ctx, sql.ListWorkloadStatusParams{
		Cluster:      req.Cluster,
		Namespace:    req.Namespace,
		WorkloadName: req.Workload,
		WorkloadType: &workloadType,
		Limit:        req.Limit,
		Offset:       req.Offset,
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
			WorkloadId:        row.ID.String(),
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

	result, err := s.resync.Resync(ctx, resync.Input{
		Cluster:       request.GetCluster(),
		Namespace:     request.GetNamespace(),
		Workload:      request.GetWorkload(),
		WorkloadType:  request.WorkloadType,
		WorkloadState: workloadState,
		ImageState:    request.ImageState,
	})
	if err != nil {
		return nil, err
	}
	if result.NumWorkloads == 0 {
		return &management.ResyncResponse{}, nil
	}
	return &management.ResyncResponse{
		NumWorkloads: result.NumWorkloads,
		Workloads:    result.Workloads,
	}, nil
}

func (s *Server) DeleteWorkload(ctx context.Context, request *management.DeleteWorkloadRequest) (*management.DeleteWorkloadResponse, error) {
	workloadType := model.WorkloadTypeApp
	if request.WorkloadType != nil {
		workloadType = model.WorkloadType(*request.WorkloadType)
	}

	w, err := s.querier.GetWorkload(ctx, sql.GetWorkloadParams{
		Cluster:      request.Cluster,
		Namespace:    request.Namespace,
		Name:         request.Workload,
		WorkloadType: string(workloadType),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Errorf(codes.NotFound, "workload %s/%s/%s not found", request.Cluster, request.Namespace, request.Workload)
		}
		s.log.WithError(err).Error("failed to get workload")
		return nil, err
	}

	workload := &model.Workload{
		Cluster:   request.Cluster,
		Namespace: request.Namespace,
		Name:      request.Workload,
		Type:      workloadType,
		ImageName: w.ImageName,
		ImageTag:  w.ImageTag,
	}

	err = s.mgr.DeleteWorkload(ctx, workload)
	if err != nil {
		s.log.WithError(err).Error("failed to delete workload")
		return nil, err
	}

	return &management.DeleteWorkloadResponse{}, nil
}
