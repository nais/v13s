// TODO: rename package to management or something else, or split up into domain specific packages
package manager

import (
	"context"
	"errors"
	"fmt"
	"go.opentelemetry.io/otel/attribute"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sigstore/cosign/v2/pkg/cosign"
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

func NewWorkloadManager(pool *pgxpool.Pool, verifier attestation.Verifier, source sources.Source, queue *kubernetes.WorkloadEventQueue, log *logrus.Entry) *WorkloadManager {
	meter := otel.GetMeterProvider().Meter("nais_v13s_manager")
	udCounter, err := meter.Int64UpDownCounter("nais_v13s_manager_resources", metric.WithDescription("Number of workloads managed by the manager"))
	if err != nil {
		panic(err)
	}
	m := &WorkloadManager{
		db:              sql.New(pool),
		pool:            pool,
		verifier:        verifier,
		src:             source,
		queue:           queue,
		workloadCounter: udCounter,
		log:             log,
	}

	m.addDispatcher = NewDispatcher(workloadWorker(m.AddWorkload), queue.Updated, maxWorkers)
	m.addDispatcher.errorHook = m.handleError
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
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: map[string]string{},
	}); err != nil {
		m.log.WithError(err).Error("Failed to create image")
		return err
	}

	row, err := m.db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			m.log.WithField("workload", workload).Debug("workload already initialized, skipping")
			return nil
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			m.log.WithError(err).Error("failed to get workload")
			return err
		}
	}
	workloadId := row.ID

	m.log.WithField("workload", workload).Debug("adding or updating workload")

	verifier := m.verifier
	att, err := verifier.GetAttestation(ctx, workload.ImageName+":"+workload.ImageTag)

	m.workloadCounter.Add(
		ctx,
		1,
		metric.WithAttributes(
			attribute.String("type", string(workload.Type)),
			attribute.String("hasAttestation", fmt.Sprint(att != nil)),
		))

	if err != nil {
		var noMatchAttestationError *cosign.ErrNoMatchingAttestations
		if errors.As(err, &noMatchAttestationError) {
			err = m.setWorkloadState(ctx, workloadId, sql.WorkloadStateNoAttestation)
			if err != nil {
				return err
			}
			return nil
		} else {
			return err
		}
	}

	if att != nil {
		err = m.db.UpdateImage(ctx, sql.UpdateImageParams{
			Name:     workload.ImageName,
			Tag:      workload.ImageTag,
			Metadata: att.Metadata,
		})
		if err != nil {
			return fmt.Errorf("failed to update image metadata: %w", err)
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
			return err
		}

		err = m.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
			SourceID: pgtype.UUID{
				Bytes: id,
				Valid: true,
			},
			WorkloadID: workloadId,
			SourceType: source.Name(),
		})
		if err != nil {
			return err
		}

	}
	err = m.setWorkloadState(ctx, workloadId, sql.WorkloadStateUpdated)
	if err != nil {
		return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
	}

	return nil
}

func (m *WorkloadManager) setWorkloadState(ctx context.Context, id pgtype.UUID, state sql.WorkloadState) error {
	err := m.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: state,
		ID:    id,
	})
	if err != nil {
		return fmt.Errorf("failed to set workload state: %w", err)
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
