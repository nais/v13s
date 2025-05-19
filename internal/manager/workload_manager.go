package manager

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/manager/domain"
	"github.com/nais/v13s/internal/manager/jobs"
	"github.com/nais/v13s/internal/manager/workers"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/service"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxWorkers = 100
)

type WorkloadEvent string

const (
	WorkloadEventFailed           WorkloadEvent = "failed"
	WorkloadEventUnrecoverable    WorkloadEvent = "unrecoverable_error"
	WorkloadEventRecoverable      WorkloadEvent = "recoverable_error"
	WorkloadEventSucceeded        WorkloadEvent = "succeeded"
	WorkloadEventSubsystemUnknown               = "unknown"
)

type WorkloadManager struct {
	db               sql.Querier
	verifier         attestation.Verifier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *Dispatcher[*model.Workload]
	deleteDispatcher *Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	svc              domain.WorkloadService
	wmgr             *jobs.WorkerManager
	log              logrus.FieldLogger
}

func NewWorkloadManager(pool *pgxpool.Pool, verifier attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, wmgr *jobs.WorkerManager, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}

	db := sql.New(pool)
	svc := service.NewWorkloadService(db, verifier, source, wmgr, udCounter, log)

	m := &WorkloadManager{
		db:              db,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		wmgr:            wmgr,
		svc:             svc,
		log:             log,
	}

	m.addDispatcher = NewDispatcher(workloadWorker(svc.AddWorkload), queue.Updated, maxWorkers)
	m.addDispatcher.errorHook = m.handleError
	m.deleteDispatcher = NewDispatcher(workloadWorker(svc.DeleteWorkload), queue.Deleted, maxWorkers)

	m.addWorkers()

	return m
}

func (m *WorkloadManager) addWorkers() {
	jobs.AddWorker(m.wmgr, &workers.AddWorkloadWorker{
		Svc: m.svc,
	})
	jobs.AddWorker(m.wmgr, &workers.GetAttestationWorker{
		Svc: m.svc,
	})
	jobs.AddWorker(m.wmgr, &workers.UploadAttestationWorker{
		Svc: m.svc,
	})
}

func (m *WorkloadManager) Start(ctx context.Context) {
	m.log.Info("starting workload manager")
	if err := m.wmgr.Start(ctx); err != nil {
		m.log.WithError(err).Fatal("failed to start worker manager")
	}
	m.addDispatcher.Start(ctx)
	m.deleteDispatcher.Start(ctx)
}

func (m *WorkloadManager) handleError(ctx context.Context, workload *model.Workload, originalErr error) {
	m.log.WithField("workload", workload.String()).WithError(originalErr).Error("processing workload")
	state := sql.WorkloadStateFailed
	subsystem := WorkloadEventSubsystemUnknown
	eventType := WorkloadEventFailed

	var uErr model.UnrecoverableError
	if errors.As(originalErr, &uErr) {
		m.log.WithField("workload", workload.String()).Error("unrecoverable error, marking workload as unrecoverable")
		subsystem = uErr.Subsystem
		state = sql.WorkloadStateUnrecoverable
		eventType = WorkloadEventUnrecoverable
	}

	var rErr model.RecoverableError
	if errors.As(originalErr, &rErr) {
		m.log.WithField("workload", workload.String()).Error("recoverable error, marking workload as failed")
		subsystem = rErr.Subsystem
		state = sql.WorkloadStateFailed
		eventType = WorkloadEventRecoverable
	}

	err := m.db.AddWorkloadEvent(ctx, sql.AddWorkloadEventParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		EventType:    string(eventType),
		EventData:    originalErr.Error(),
		Subsystem:    subsystem,
	})
	if err != nil {
		m.log.WithError(err).WithField("workload", workload).Error("failed to add workload event")
	}

	err = m.db.SetWorkloadState(ctx, sql.SetWorkloadStateParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
		State:        state,
	})
	if err != nil {
		m.log.WithError(err).WithField("workload", workload).Error("failed to set workload state")
	}
}

func (m *WorkloadManager) Stop(ctx context.Context) error {
	return m.wmgr.Stop(ctx)
}

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}
