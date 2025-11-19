package postgresriver

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
	"github.com/nais/v13s/internal/postgresriver/riverjob/worker"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxWorkers = 60
)

type WorkloadManager struct {
	db               sql.Querier
	pool             *pgxpool.Pool
	jobClient        riverjob.Client
	verifier         attestation.Verifier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *manager.Dispatcher[*model.Workload]
	deleteDispatcher *manager.Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	log              logrus.FieldLogger
}

type WorkloadEvent string

type WorkloadManagerConfig struct {
	Pool      *pgxpool.Pool
	JobConfig *riverjob.Options
	Verifier  attestation.Verifier
	Source    sources.Source
	Queue     *kubernetes.WorkloadEventQueue
	Logger    logrus.FieldLogger
	Meter     metric.Meter
}

func NewWorkloadManager(ctx context.Context, cfg WorkloadManagerConfig) (*WorkloadManager, error) {
	if cfg.Pool == nil {
		return nil, errors.New("pool is required")
	}
	if cfg.JobConfig == nil {
		return nil, errors.New("job config is required")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("verifier is required")
	}
	if cfg.Source == nil {
		return nil, errors.New("source is required")
	}
	if cfg.Queue == nil {
		return nil, errors.New("workload event queue is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}

	log := cfg.Logger.WithField("component", "workload_manager")

	meter := cfg.Meter
	if meter == nil {
		meter = otel.GetMeterProvider().Meter("nais_v13s_manager")
	}

	workloadCounter, err := meter.Int64UpDownCounter(
		"nais_v13s_manager_resources",
		metric.WithDescription("Number of workloads managed by the manager"),
	)
	if err != nil {
		return nil, fmt.Errorf("create workload counter: %w", err)
	}

	db := sql.New(cfg.Pool)

	// Queue configuration for all job kinds handled by this manager.
	queues := defaultQueueConfig()

	jobClient, err := riverjob.NewClient(ctx, cfg.JobConfig, queues)
	if err != nil {
		return nil, fmt.Errorf("create job client: %w", err)
	}

	// Register all workers for the job client.
	registerWorkers(jobClient, workerDeps{
		db:              db,
		source:          cfg.Source,
		verifier:        cfg.Verifier,
		workloadCounter: workloadCounter,
		log:             log,
	})

	mgr := &WorkloadManager{
		db:              db,
		pool:            cfg.Pool,
		jobClient:       jobClient,
		verifier:        cfg.Verifier,
		src:             cfg.Source,
		queue:           cfg.Queue,
		workloadCounter: workloadCounter,
		log:             log,
	}

	mgr.addDispatcher = manager.NewDispatcher(
		workloadWorker(mgr.AddWorkload),
		cfg.Queue.Updated,
		maxWorkers,
	)

	mgr.deleteDispatcher = manager.NewDispatcher(
		workloadWorker(mgr.DeleteWorkload),
		cfg.Queue.Deleted,
		maxWorkers,
	)

	return mgr, nil
}

func defaultQueueConfig() map[string]river.QueueConfig {
	return map[string]river.QueueConfig{
		job.KindAddWorkload:                     {MaxWorkers: 20},
		job.KindGetAttestation:                  {MaxWorkers: 25},
		job.KindUploadAttestation:               {MaxWorkers: 10},
		job.KindDeleteWorkload:                  {MaxWorkers: 3},
		job.KindRemoveFromSource:                {MaxWorkers: 3},
		job.KindFinalizeAttestation:             {MaxWorkers: 10},
		job.KindUpsertVulnerabilitySummaries:    {MaxWorkers: 3},
		job.KindFetchVulnerabilityDataForImages: {MaxWorkers: 3},
		job.KindFinalizeAnalysisBatch:           {MaxWorkers: 5},
		job.KindProcessVulnerabilityDataBatch:   {MaxWorkers: 3},
	}
}

type workerDeps struct {
	db              sql.Querier
	source          sources.Source
	verifier        attestation.Verifier
	workloadCounter metric.Int64UpDownCounter
	log             logrus.FieldLogger
}

func registerWorkers(jobClient riverjob.Client, deps workerDeps) {
	log := deps.log

	riverjob.AddWorker(jobClient, &worker.AddWorkloadWorker{
		Querier:   deps.db,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindAddWorkload),
	})

	riverjob.AddWorker(jobClient, &worker.GetAttestationWorker{
		Querier:         deps.db,
		Verifier:        deps.verifier,
		JobClient:       jobClient,
		WorkloadCounter: deps.workloadCounter,
		Log:             log.WithField("subsystem", job.KindGetAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.UploadAttestationWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindUploadAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.RemoveFromSourceWorker{
		Querier: deps.db,
		Source:  deps.source,
		Log:     log.WithField("subsystem", job.KindRemoveFromSource),
	})

	riverjob.AddWorker(jobClient, &worker.DeleteWorkloadWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindDeleteWorkload),
	})

	riverjob.AddWorker(jobClient, &worker.FinalizeAttestationWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFinalizeAttestation),
	})

	riverjob.AddWorker(jobClient, &worker.UpsertVulnerabilitySummariesWorker{
		Querier: deps.db,
		Source:  deps.source,
		Log:     log.WithField("subsystem", job.KindUpsertVulnerabilitySummaries),
	})

	riverjob.AddWorker(jobClient, &worker.FetchVulnerabilityDataForImagesWorker{
		Querier:   deps.db,
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFetchVulnerabilityDataForImages),
	})

	riverjob.AddWorker(jobClient, &worker.FinalizeAnalysisBatchWorker{
		Source:    deps.source,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindFinalizeAnalysisBatch),
	})

	riverjob.AddWorker(jobClient, &worker.ProcessVulnerabilityDataBatchWorker{
		Querier:   deps.db,
		JobClient: jobClient,
		Log:       log.WithField("subsystem", job.KindProcessVulnerabilityDataBatch),
	})
}

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) manager.Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
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
	return m.jobClient.AddJob(ctx, &job.AddWorkloadJob{
		Workload: workload,
	})
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	return m.jobClient.AddJob(ctx, &job.DeleteWorkloadJob{
		Workload: workload,
	})
}

func (m *WorkloadManager) AddJob(ctx context.Context, j river.JobArgs) error {
	return m.jobClient.AddJob(ctx, j)
}
