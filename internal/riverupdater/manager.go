package riverupdater

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const maxWorkers = 60

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

	db, jobClient, err := setupJobsAndWorkers(ctx, cfg, log, workloadCounter)
	if err != nil {
		return nil, err
	}

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
