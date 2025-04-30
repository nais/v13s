// TODO: rename package to management or something else, or split up into domain specific packages
package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	maxWorkers = 10
)

type WorkloadManager struct {
	db               sql.Querier
	verifier         *attestation.Verifier
	src              sources.Source
	queue            *kubernetes.WorkloadEventQueue
	addDispatcher    *Dispatcher[*model.Workload]
	deleteDispatcher *Dispatcher[*model.Workload]
	workloadCounter  metric.Int64UpDownCounter
	log              logrus.FieldLogger
}

func NewWorkloadManager(querier sql.Querier, verifier *attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}
	m := &WorkloadManager{
		db:              querier,
		verifier:        verifier,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		log:             log,
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
	row, err := m.db.GetWorkload(ctx, sql.GetWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			m.log.WithError(err).Error("Failed to get workload")
			return err
		}
	}

	if row != nil && workload.ImageTag == row.ImageTag {
		m.log.Debugf("workload already exists and image tag is the same, skipping: %s", workload.Name)
		return nil
	}

	m.log.WithField("workload", workload).Debug("adding or updating workload")
	// TODO: add metadata to workload
	workloadId, err := m.RegisterWorkload(ctx, workload, map[string]string{})
	if err != nil {
		m.log.WithError(err).Error("Failed to register workload")
		return err
	}

	verifier := m.verifier
	att, err := verifier.GetAttestation(ctx, workload.ImageName+":"+workload.ImageTag)

	if err != nil {
		if !strings.Contains(err.Error(), attestation.ErrNoAttestation) {
			m.log.WithError(err).Warn("Failed to get attestation")
		}
	}

	m.workloadCounter.Add(
		ctx,
		1,
		metric.WithAttributes(
			attribute.String("type", string(workload.Type)),
			attribute.String("hasAttestation", fmt.Sprint(att != nil)),
		))

	if os.Getenv("DISABLE_SBOM_UPDATE") != "" {
		m.log.Debug("skipping sbom update")
		return nil
	}

	if att != nil {
		err = m.db.UpdateImage(ctx, sql.UpdateImageParams{
			Name:     workload.ImageName,
			Tag:      workload.ImageTag,
			Metadata: att.Metadata,
		})
		if err != nil {
			m.log.WithError(err).Error("Failed to update image metadata")
		}

		source := m.src
		sw := &sources.Workload{
			Cluster:   workload.Cluster,
			Namespace: workload.Namespace,
			Name:      workload.Name,
			Type:      string(workload.Type),
			ImageName: workload.ImageName,
			ImageTag:  workload.ImageTag,
		}
		id, err := source.UploadAttestation(ctx, sw, att.Statement)
		if err != nil {
			m.log.WithError(err).Error("Failed to upload sbom")
			return err
		}

		err = m.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
			SourceID: pgtype.UUID{
				Bytes: id,
				Valid: true,
			},
			WorkloadID: *workloadId,
			SourceType: source.Name(),
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *WorkloadManager) DeleteWorkload(ctx context.Context, w *model.Workload) error {
	m.log.WithField("workload", w).Debug("deleting workload")
	id, err := m.db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		m.log.WithError(err).Error("Failed to delete workload")
		return err
	}

	refs, err := m.db.ListSourceRefs(ctx, sql.ListSourceRefsParams{
		WorkloadID: id,
		SourceType: m.src.Name(),
	})
	if err != nil {
		m.log.WithError(err).Error("Failed to list source refs")
		return err
	}
	for _, ref := range refs {
		sw := &sources.Workload{
			Cluster:   w.Cluster,
			Namespace: w.Namespace,
			Name:      w.Name,
			Type:      string(w.Type),
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		}

		// TODO: functionality that ensures that the workload is deleted from the source
		// TODO: either a table that collects workload deletion failures or a retry mechanism
		err = m.src.DeleteWorkload(ctx, ref.SourceID.Bytes, sw)
		if err != nil {
			m.log.WithError(err).Error("Failed to delete workload from source")
			return err
		}
	}
	return nil
}

func (m *WorkloadManager) RegisterWorkload(ctx context.Context, workload *model.Workload, metadata map[string]string) (*pgtype.UUID, error) {
	if err := m.db.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: metadata,
	}); err != nil {
		m.log.WithError(err).Error("Failed to create image")
		return nil, err
	}

	id, err := m.db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
		Name:         workload.Name,
		WorkloadType: string(workload.Type),
		Namespace:    workload.Namespace,
		Cluster:      workload.Cluster,
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})

	if err != nil {
		m.log.WithError(err).Error("Failed to upsert workload")
		return nil, err
	}

	return &id, err
}
