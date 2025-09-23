package management

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/dispatcher"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/jobs/registry"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxWorkers = 100
)

type WorkloadManager struct {
	db               sql.Querier
	pool             *pgxpool.Pool
	jobClient        job.Client
	verifier         attestation.Verifier
	srcs             map[string]sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *dispatcher.Dispatcher[*model.Workload]
	deleteDispatcher *dispatcher.Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	log              logrus.FieldLogger
}

type WorkloadEvent string

func NewWorkloadManager(ctx context.Context, pool *pgxpool.Pool, jobOpts *job.Options, verifier attestation.Verifier, s map[string]sources.Source, queue *kubernetes.WorkloadEventQueue, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}
	db := sql.New(pool)

	queues := map[string]river.QueueConfig{
		types.KindAddWorkload:         {MaxWorkers: 100},
		types.KindGetAttestation:      {MaxWorkers: 100},
		types.KindUploadAttestation:   {MaxWorkers: 100},
		types.KindDeleteWorkload:      {MaxWorkers: 100},
		types.KindRemoveFromSource:    {MaxWorkers: 100},
		types.KindFinalizeAttestation: {MaxWorkers: 100},
		types.KindUpsertImage:         {MaxWorkers: 50},
		types.KindFetchImage:          {MaxWorkers: 50},
	}

	jobClient, err := job.NewClient(ctx, jobOpts, queues)
	if err != nil {
		log.Fatalf("Failed to create job client: %v", err)
	}

	m := &WorkloadManager{
		db:              db,
		pool:            pool,
		jobClient:       jobClient,
		verifier:        verifier,
		srcs:            s,
		queue:           queue,
		workloadCounter: udCounter,
		log:             log,
	}

	registry.RegisterWorkers(jobClient, db, verifier, s, m, log, udCounter)
	m.addDispatcher = dispatcher.NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	m.deleteDispatcher = dispatcher.NewDispatcher(workloadWorker(m.DeleteWorkload), queue.Deleted, maxWorkers)
	return m
}

func (m *WorkloadManager) Start(ctx context.Context) {
	m.log.Info("starting workload manager")
	if err := m.jobClient.Start(ctx); err != nil {
		m.log.WithError(err).Fatal("failed to start worker manager")
	}
	m.addDispatcher.Start(ctx)
	m.deleteDispatcher.Start(ctx)
}

func (m *WorkloadManager) Stop(ctx context.Context) error {
	return m.jobClient.Stop(ctx)
}

func (m *WorkloadManager) AddWorkload(ctx context.Context, workload *model.Workload) error {
	m.log.WithField("workload", workload).Debug("adding or updating workload")
	err := m.jobClient.AddJob(ctx, &types.AddWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	err := m.jobClient.AddJob(ctx, &types.DeleteWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) SyncImage(ctx context.Context, imageName, imageTag string) error {
	err := m.jobClient.AddJob(ctx, &types.FetchImageJob{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) AddJob(ctx context.Context, job river.JobArgs) error {
	return m.jobClient.AddJob(ctx, job)
}

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) dispatcher.Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}
