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
	maxWorkers = 40
)

type WorkloadManager struct {
	db                sql.Querier
	pool              *pgxpool.Pool
	jobClient         job.Client
	verifier          attestation.Verifier
	src               sources.Source
	queue             *kubernetes.WorkloadEventQueue
	addDispatcher     *Dispatcher[*model.Workload]
	deleteDispatcher  *Dispatcher[*model.Workload]
	workloadCounter   metric.Int64UpDownCounter
	reconcileDryRun   bool
	log               logrus.FieldLogger
}

type WorkloadEvent string

const (
	WorkloadEventFailed           WorkloadEvent = "failed"
	WorkloadEventUnrecoverable    WorkloadEvent = "unrecoverable_error"
	WorkloadEventRecoverable      WorkloadEvent = "recoverable_error"
	WorkloadEventSucceeded        WorkloadEvent = "succeeded"
	WorkloadEventSubsystemUnknown               = "unknown"
)

func NewWorkloadManager(ctx context.Context, pool *pgxpool.Pool, jobCfg *job.Config, verifier attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, dryRun bool, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}
	db := sql.New(pool)

	queues := map[string]river.QueueConfig{
		KindAddWorkload:             {MaxWorkers: 8},
		model.JobKindGetAttestation: {MaxWorkers: 25},
		KindUploadAttestation:       {MaxWorkers: 5},
		KindDeleteWorkload:          {MaxWorkers: 3},
		KindRemoveFromSource:        {MaxWorkers: 3},
		KindFinalizeAttestation:     {MaxWorkers: 10},
	}

	jobClient, err := job.NewClient(ctx, jobCfg, queues)
	if err != nil {
		log.Fatalf("Failed to create job client: %v", err)
	}
	job.AddWorker(jobClient, &AddWorkloadWorker{db: db, jobClient: jobClient, log: log.WithField("subsystem", "add_workload")})
	job.AddWorker(jobClient, &GetAttestationWorker{db: db, verifier: verifier, jobClient: jobClient, workloadCounter: udCounter, log: log.WithField("subsystem", model.JobKindGetAttestation)})
	job.AddWorker(jobClient, &UploadAttestationWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", "upload_attestation")})
	job.AddWorker(jobClient, &RemoveFromSourceWorker{db: db, source: source, log: log.WithField("subsystem", "remove_from_source")})
	job.AddWorker(jobClient, &DeleteWorkloadWorker{db: db, jobClient: jobClient, log: log.WithField("subsystem", "delete_workload")})
	job.AddWorker(jobClient, &FinalizeAttestationWorker{db: db, source: source, jobClient: jobClient, log: log.WithField("subsystem", "finalize_attestation")})
	m := &WorkloadManager{
		db:              db,
		pool:            pool,
		jobClient:       jobClient,
		verifier:        verifier,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		reconcileDryRun: dryRun,
		log:             log,
	}
	m.addDispatcher = NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	// m.addDispatcher.errorHook = m.handleError
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

func (m *WorkloadManager) AddJob(ctx context.Context, job river.JobArgs) error {
	return m.jobClient.AddJob(ctx, job)
}

// ReconcileWorkloads compares DB workloads against the live k8s state and
// enqueues DeleteWorkloadJob for any workload that no longer exists in k8s.
// Only clusters present in liveByCluster are reconciled — clusters not managed
// by the informer are left untouched.
// When reconcileDryRun is true (default), no deletions are enqueued — only logged.
func (m *WorkloadManager) ReconcileWorkloads(ctx context.Context, liveByCluster map[string][]*model.Workload) {
	for cluster, liveWorkloads := range liveByCluster {
		live := make(map[string]bool, len(liveWorkloads))
		for _, w := range liveWorkloads {
			live[w.Name+"/"+w.Namespace+"/"+string(w.Type)] = true
		}

		dbWorkloads, err := m.db.ListWorkloadsByCluster(ctx, cluster)
		if err != nil {
			m.log.WithError(err).Errorf("reconcile: failed to list workloads for cluster %s", cluster)
			continue
		}

		for _, dbW := range dbWorkloads {
			key := dbW.Name + "/" + dbW.Namespace + "/" + dbW.WorkloadType
			if live[key] {
				continue
			}
			if m.reconcileDryRun {
				m.log.Infof("[DRY RUN] reconcile: would delete workload %s/%s (not found in k8s)", cluster, key)
				continue
			}
			m.log.Infof("[DELETE] reconcile: workload %s/%s not found in k8s, enqueuing delete", cluster, key)
			if err := m.DeleteWorkload(ctx, &model.Workload{
				Name:      dbW.Name,
				Namespace: dbW.Namespace,
				Cluster:   dbW.Cluster,
				Type:      model.WorkloadType(dbW.WorkloadType),
			}); err != nil {
				m.log.WithError(err).Warnf("reconcile: failed to enqueue delete for %s/%s", cluster, key)
			}
		}
	}
}

func (m *WorkloadManager) Stop(ctx context.Context) error {
	return m.jobClient.Stop(ctx)
}
