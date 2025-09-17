// TODO: rename package to management or something else, or split up into domain specific packages
package manager

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
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
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *Dispatcher[*model.Workload]
	deleteDispatcher *Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	log              logrus.FieldLogger
}

type WorkloadEvent string

const (
	WorkloadEventFailed           WorkloadEvent = "failed"
	WorkloadEventUnrecoverable    WorkloadEvent = "unrecoverable_error"
	WorkloadEventRecoverable      WorkloadEvent = "recoverable_error"
	WorkloadEventSucceeded        WorkloadEvent = "succeeded"
	WorkloadEventSubsystemUnknown               = "unknown"
)

func NewWorkloadManager(ctx context.Context, pool *pgxpool.Pool, jobCfg *job.Config, verifier attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}
	db := sql.New(pool)

	queues := map[string]river.QueueConfig{
		KindAddWorkload: {
			MaxWorkers: 100,
		},
		KindGetAttestation: {
			MaxWorkers: 100,
		},
		KindUploadAttestation: {
			MaxWorkers: 100,
		},
		KindDeleteWorkload: {
			MaxWorkers: 100,
		},
		KindRemoveFromSource: {
			MaxWorkers: 100,
		},
		KindFinalizeAttestation: {
			MaxWorkers: 100,
		},
		KindUpsertImage: {
			MaxWorkers: 50,
		},
		KindFetchImage: {
			MaxWorkers: 50,
		},
	}

	jobClient, err := job.NewClient(ctx, jobCfg, queues)
	if err != nil {
		log.Fatalf("Failed to create job client: %v", err)
	}
	job.AddWorker(jobClient, &AddWorkloadWorker{db: db, jobClient: jobClient, log: log.WithField("subsystem", KindAddWorkload)})
	job.AddWorker(jobClient, &GetAttestationWorker{db: db, verifier: verifier, jobClient: jobClient, workloadCounter: udCounter, log: log.WithField("subsystem", KindGetAttestation)})
	job.AddWorker(jobClient, &UploadAttestationWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", KindUploadAttestation)})
	job.AddWorker(jobClient, &RemoveFromSourceWorker{db: db, source: source, log: log.WithField("subsystem", KindRemoveFromSource)})
	job.AddWorker(jobClient, &DeleteWorkloadWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", KindDeleteWorkload)})
	job.AddWorker(jobClient, &FinalizeAttestationWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", KindFinalizeAttestation)})
	job.AddWorker(jobClient, &FetchImageWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", KindFetchImage)})
	job.AddWorker(jobClient, &UpsertImageWorker{db: db, log: log.WithField("subsystem", KindUpsertImage)})

	m := &WorkloadManager{
		db:              db,
		pool:            pool,
		jobClient:       jobClient,
		verifier:        verifier,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		log:             log,
	}
	m.addDispatcher = NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	//m.addDispatcher.errorHook = m.handleError
	m.deleteDispatcher = NewDispatcher(workloadWorker(m.DeleteWorkload), queue.Deleted, maxWorkers)

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

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}

func (m *WorkloadManager) AddWorkload(ctx context.Context, workload *model.Workload) error {
	m.log.WithField("workload", workload).Debug("adding or updating workload")
	err := m.jobClient.AddJob(ctx, &AddWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	err := m.jobClient.AddJob(ctx, &DeleteWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) SyncImage(ctx context.Context, imageName, imageTag string) error {
	err := m.jobClient.AddJob(ctx, &FetchImageJob{
		ImageName: imageName,
		ImageTag:  imageTag,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) Stop(ctx context.Context) error {
	return m.jobClient.Stop(ctx)
}
