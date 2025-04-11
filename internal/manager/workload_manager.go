// TODO: rename package to management or something else, or split up into domain specific packages
package manager

import (
	"context"

	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
)

const (
	maxWorkers = 10
)

type WorkloadManager struct {
	db               sql.Querier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *Dispatcher[*model.Workload]
	deleteDispatcher *Dispatcher[*model.Workload]
	log              logrus.FieldLogger
}

func NewWorkloadManager(querier sql.Querier, source sources.Source, queue *kubernetes.WorkloadEventQueue, log *logrus.Entry) *WorkloadManager {
	m := &WorkloadManager{
		db:    querier,
		src:   source,
		queue: queue,
		log:   log,
	}

	m.addDispatcher = NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	m.deleteDispatcher = NewDispatcher(workloadWorker(m.DeleteWorkload), queue.Deleted, maxWorkers)
	return m
}

func (m *WorkloadManager) Start(ctx context.Context) {
	m.log.Info("starting workload manager")
	m.addDispatcher.Start(ctx)
	m.deleteDispatcher.Start(ctx)
}

func workloadWorker(fn func(ctx context.Context, w *model.Workload) error) Worker[*model.Workload] {
	return func(ctx context.Context, workload *model.Workload) error {
		return fn(ctx, workload)
	}
}

func (m *WorkloadManager) AddWorkload(ctx context.Context, workload *model.Workload) error {
	if err := m.db.CreateImage(ctx, sql.CreateImageParams{
		Name: workload.ImageName,
		Tag:  workload.ImageTag,
		// TODO: add metadata or move metadata to workload?
		Metadata: map[string]string{},
	}); err != nil {
		m.log.WithError(err).Error("Failed to create image")
		return err
	}

	isPlatformImage := collections.AnyMatch([]string{
		"gcr.io/cloud-sql-connectors/cloud-sql-proxy",
		"docker.io/devopsfaith/krakend",
		"europe-north1-docker.pkg.dev/nais-io/nais/images/elector",
	}, func(e string) bool {
		return e == workload.ImageName || workload.Name == "wonderwall"
	})

	wType := workload.Type
	if isPlatformImage {
		wType = model.WorkloadTypePlatform
	}

	if err := m.db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         workload.Name,
		WorkloadType: string(wType),
		Namespace:    workload.Namespace,
		Cluster:      workload.Cluster,
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	}); err != nil {
		m.log.WithError(err).Error("Failed to upsert workload")
		return err
	}

	return nil
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, w *model.Workload) error {
	m.log.WithField("workload", w).Debug("deleting workload")
	err := m.db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		m.log.WithError(err).Error("Failed to delete workload")
		return err
	}
	return nil
}
