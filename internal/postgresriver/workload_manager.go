// TODO: rename package to management or something else, or split up into domain specific packages
package postgresriver

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/job/workers"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxWorkers = 40
)

type WorkloadManager struct {
	db               sql.Querier
	pool             *pgxpool.Pool
	jobClient        job.Client
	verifier         attestation.Verifier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *manager.Dispatcher[*model.Workload]
	deleteDispatcher *manager.Dispatcher[*model.Workload]
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
		manager.KindAddWorkload:                  {MaxWorkers: 10},
		manager.KindGetAttestation:               {MaxWorkers: 15},
		manager.KindUploadAttestation:            {MaxWorkers: 10},
		manager.KindDeleteWorkload:               {MaxWorkers: 3},
		manager.KindRemoveFromSource:             {MaxWorkers: 3},
		manager.KindFinalizeAttestation:          {MaxWorkers: 10},
		manager.KindUpsertVulnerabilitySummaries: {MaxWorkers: 8},
		jobs.KindFetchVulnerabilityDataForImages: {MaxWorkers: 10},
		jobs.KindFinalizeAnalysis:                {MaxWorkers: 5},
		jobs.KindProcessVulnerabilityData:        {MaxWorkers: 10},
	}

	jobClient, err := job.NewClient(ctx, jobCfg, queues)
	if err != nil {
		log.Fatalf("Failed to create job client: %v", err)
	}
	job.AddWorker(jobClient, &manager.AddWorkloadWorker{Querier: db, JobClient: jobClient, Log: log.WithField("subsystem", "add_workload")})
	job.AddWorker(jobClient, &manager.GetAttestationWorker{Querier: db, Verifier: verifier, JobClient: jobClient, WorkloadCounter: udCounter, Log: log.WithField("subsystem", "get_attestation")})
	job.AddWorker(jobClient, &manager.UploadAttestationWorker{Querier: db, Source: source, JobClient: jobClient, Log: log.WithField("subsystem", "upload_attestation")})
	job.AddWorker(jobClient, &manager.RemoveFromSourceWorker{Querier: db, Source: source, Log: log.WithField("subsystem", "remove_from_source")})
	job.AddWorker(jobClient, &manager.DeleteWorkloadWorker{Querier: db, Source: source, JobClient: jobClient, Log: log.WithField("subsystem", "delete_workload")})
	job.AddWorker(jobClient, &manager.FinalizeAttestationWorker{Querier: db, Source: source, JobClient: jobClient, Log: log.WithField("subsystem", "finalize_attestation")})
	job.AddWorker(jobClient, &manager.UpsertVulnerabilitySummariesWorker{Querier: db, Source: source, Log: log.WithField("subsystem", "upsert_vulnerability_summaries")})
	job.AddWorker(jobClient, &workers.FetchVulnerabilityDataForImagesWorker{Querier: db, Source: source, JobClient: jobClient, Log: log.WithField("subsystem", jobs.KindFetchVulnerabilityDataForImages)})
	job.AddWorker(jobClient, &workers.FinalizeAnalysisWorker{Source: source, JobClient: jobClient, Log: log.WithField("subsystem", jobs.KindFinalizeAnalysis)})
	job.AddWorker(jobClient, &workers.ProcessVulnerabilityDataWorker{Querier: db, JobClient: jobClient, Log: log.WithField("subsystem", jobs.KindProcessVulnerabilityData)})
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
	m.addDispatcher = manager.NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	//m.addDispatcher.errorHook = m.handleError
	m.deleteDispatcher = manager.NewDispatcher(workloadWorker(m.DeleteWorkload), queue.Deleted, maxWorkers)

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

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) manager.Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}

func (m *WorkloadManager) AddWorkload(ctx context.Context, workload *model.Workload) error {
	m.log.WithField("workload", workload).Debug("adding or updating workload")
	err := m.jobClient.AddJob(ctx, &manager.AddWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, workload *model.Workload) error {
	err := m.jobClient.AddJob(ctx, &manager.DeleteWorkloadJob{
		Workload: workload,
	})
	if err != nil {
		return err
	}
	return nil
}

func (m *WorkloadManager) AddJob(ctx context.Context, job river.JobArgs) error {
	return m.jobClient.AddJob(ctx, job)
}

/*func (m *WorkloadManager) handleError(ctx context.Context, workload *model.Workload, originalErr error) {
	m.Log.WithField("workload", workload.String()).WithError(originalErr).Error("processing workload")
	state := sql.WorkloadStateFailed
	subsystem := WorkloadEventSubsystemUnknown
	eventType := WorkloadEventFailed

	var uErr model.UnrecoverableError
	if errors.As(originalErr, &uErr) {
		m.Log.WithField("workload", workload.String()).Error("unrecoverable error, marking workload as unrecoverable")
		subsystem = uErr.Subsystem
		state = sql.WorkloadStateUnrecoverable
		eventType = WorkloadEventUnrecoverable
	}

	var rErr model.RecoverableError
	if errors.As(originalErr, &rErr) {
		m.Log.WithField("workload", workload.String()).Error("recoverable error, marking workload as failed")
		subsystem = rErr.Subsystem
		state = sql.WorkloadStateFailed
		eventType = WorkloadEventRecoverable
	}

	err := m.Db.AddWorkloadEvent(ctx, sql.AddWorkloadEventParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		EventType:    string(eventType),
		EventData:    originalErr.Error(),
		Subsystem:    subsystem,
	})
	if err != nil {
		m.Log.WithError(err).WithField("workload", workload).Error("failed to add workload event")
	}

	err = m.Db.SetWorkloadState(ctx, sql.SetWorkloadStateParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
		State:        state,
	})
	if err != nil {
		m.Log.WithError(err).WithField("workload", workload).Error("failed to set workload state")
	}
}*/

func (m *WorkloadManager) Stop(ctx context.Context) error {
	return m.jobClient.Stop(ctx)
}
