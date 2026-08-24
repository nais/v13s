// TODO: rename package to management or something else, or split up into domain specific packages
package manager

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

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
	db                       sql.Querier
	pool                     *pgxpool.Pool
	jobClient                job.Client
	verifier                 attestation.Verifier
	src                      sources.Source
	queue                    *kubernetes.WorkloadEventQueue
	addDispatcher            *Dispatcher[*model.Workload]
	deleteDispatcher         *Dispatcher[*model.Workload]
	workloadCounter          metric.Int64UpDownCounter
	reconcileDeletionEnabled bool
	log                      logrus.FieldLogger
	mu                       sync.Mutex
	started                  bool
	runCancel                context.CancelFunc
}

type WorkloadEvent string

const (
	WorkloadEventFailed           WorkloadEvent = "failed"
	WorkloadEventUnrecoverable    WorkloadEvent = "unrecoverable_error"
	WorkloadEventRecoverable      WorkloadEvent = "recoverable_error"
	WorkloadEventSucceeded        WorkloadEvent = "succeeded"
	WorkloadEventSubsystemUnknown               = "unknown"
)

func NewWorkloadManager(ctx context.Context, pool *pgxpool.Pool, jobCfg *job.Config, verifier attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, reconcileDeletionEnabled bool, log *logrus.Entry) *WorkloadManager {
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
	m := &WorkloadManager{
		db:                       db,
		pool:                     pool,
		jobClient:                jobClient,
		verifier:                 verifier,
		src:                      source,
		queue:                    queue,
		workloadCounter:          udCounter,
		reconcileDeletionEnabled: reconcileDeletionEnabled,
		log:                      log,
	}
	m.addDispatcher = NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	// m.addDispatcher.errorHook = m.handleError
	m.deleteDispatcher = NewDispatcher(workloadWorker(m.DeleteWorkload), queue.Deleted, maxWorkers)

	return m
}

func (m *WorkloadManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("workload manager already started")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	m.started = true
	m.runCancel = cancel
	m.mu.Unlock()

	m.log.Info("starting workload manager")
	m.registerWorkers()
	if err := m.jobClient.Start(runCtx); err != nil {
		m.mu.Lock()
		m.started = false
		m.runCancel = nil
		m.mu.Unlock()
		m.log.WithError(err).Error("failed to start worker manager")
		cancel()
		return err
	}
	m.addDispatcher.Start(runCtx)
	m.deleteDispatcher.Start(runCtx)
	return nil
}

func (m *WorkloadManager) registerWorkers() {
	job.AddWorker(m.jobClient, &AddWorkloadWorker{db: m.db, jobClient: m.jobClient, log: m.log.WithField("subsystem", "add_workload")})
	job.AddWorker(m.jobClient, &GetAttestationWorker{db: m.db, verifier: m.verifier, jobClient: m.jobClient, workloadCounter: m.workloadCounter, log: m.log.WithField("subsystem", model.JobKindGetAttestation)})
	job.AddWorker(m.jobClient, &UploadAttestationWorker{db: m.db, source: m.src, jobClient: m.jobClient, log: m.log.WithField("subsystem", "upload_attestation")})
	job.AddWorker(m.jobClient, &RemoveFromSourceWorker{db: m.db, source: m.src, log: m.log.WithField("subsystem", "remove_from_source")})
	job.AddWorker(m.jobClient, &DeleteWorkloadWorker{db: m.db, jobClient: m.jobClient, log: m.log.WithField("subsystem", "delete_workload")})
	job.AddWorker(m.jobClient, &FinalizeAttestationWorker{db: m.db, source: m.src, jobClient: m.jobClient, log: m.log.WithField("subsystem", "finalize_attestation")})
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

// Only clusters present in liveByCluster are reconciled — clusters not managed
// by the informer are left untouched.
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

		orphanTotal := 0
		enqueuedTotal := 0
		orphanByType := make(map[string]int)

		for _, dbW := range dbWorkloads {
			key := dbW.Name + "/" + dbW.Namespace + "/" + dbW.WorkloadType
			if live[key] {
				continue
			}
			orphanTotal++
			orphanByType[dbW.WorkloadType]++
			if !m.reconcileDeletionEnabled {
				m.log.Infof("[DRY RUN] reconcile: would delete workload %s/%s (not found in k8s)", cluster, key)
				continue
			}
			m.log.Infof("[DELETE] reconcile: workload %s/%s not found in k8s, enqueuing delete", cluster, key)
			if err := m.DeleteWorkload(ctx, &model.Workload{
				Name:      dbW.Name,
				Namespace: dbW.Namespace,
				Cluster:   dbW.Cluster,
				Type:      model.WorkloadType(dbW.WorkloadType),
				ImageName: dbW.ImageName,
				ImageTag:  dbW.ImageTag,
			}); err != nil {
				m.log.WithError(err).Warnf("reconcile: failed to enqueue delete for %s/%s", cluster, key)
				continue
			}
			enqueuedTotal++
		}

		mode := "dry-run"
		if m.reconcileDeletionEnabled {
			mode = "delete"
		}

		m.log.WithFields(logrus.Fields{
			"cluster":         cluster,
			"mode":            mode,
			"orphans_total":   orphanTotal,
			"orphans_by_type": formatTypeCounts(orphanByType),
			"enqueued_total":  enqueuedTotal,
		}).Info("reconcile summary")
	}
}

func formatTypeCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, ",")
}

func (m *WorkloadManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	runCancel := m.runCancel
	started := m.started
	m.started = false
	m.runCancel = nil
	m.mu.Unlock()

	if !started {
		return nil
	}

	if runCancel != nil {
		runCancel()
	}
	m.addDispatcher.Wait()
	m.deleteDispatcher.Wait()

	return m.jobClient.Stop(ctx)
}
