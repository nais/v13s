package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/manager/domain"
	"github.com/nais/v13s/internal/manager/jobs"
	"github.com/nais/v13s/internal/manager/workers"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"time"
)

var _ domain.WorkloadService = (*Service)(nil)

type Service struct {
	db              sql.Querier
	verifier        attestation.Verifier
	src             sources.Source
	wmgr            *jobs.WorkerManager
	workloadCounter metric.Int64UpDownCounter
	log             logrus.FieldLogger
}

func NewWorkloadService(db sql.Querier, verifier attestation.Verifier, src sources.Source, wmgr *jobs.WorkerManager, workloadCounter metric.Int64UpDownCounter, log logrus.FieldLogger) domain.WorkloadService {
	return &Service{
		db:              db,
		verifier:        verifier,
		src:             src,
		wmgr:            wmgr,
		workloadCounter: workloadCounter,
		log:             log,
	}
}

func (s *Service) AddWorkload(ctx context.Context, workload *model.Workload) error {
	if err := s.db.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: map[string]string{},
	}); err != nil {
		s.log.WithError(err).Error("Failed to create image")
		return err
	}

	row, err := s.db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.log.WithField("workload", workload).Debug("workload already initialized, skipping")
			return nil
		}
		s.log.WithError(err).Error("failed to initialize workload")
		return err
	}

	s.log.WithField("workload", workload).Debug("workload initialized")

	err = s.wmgr.InsertJob(ctx, workers.GetAttestationArgs{
		Workload:   workload,
		WorkloadId: row.ID,
	})
	if err != nil {
		s.log.WithError(err).Error("failed to enqueue attestation job")
	}
	return nil
}

func (s *Service) GetAttestation(ctx context.Context, workload *model.Workload, workloadId pgtype.UUID) error {
	att, err := s.verifier.GetAttestation(ctx, workload.ImageName+":"+workload.ImageTag)
	s.workloadCounter.Add(
		ctx,
		1,
		metric.WithAttributes(
			attribute.String("workload", workload.Name),
			attribute.String("hasAttestation", fmt.Sprint(att != nil)),
		))

	insertCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err != nil {
		var noMatchAttestationError *cosign.ErrNoMatchingAttestations
		if errors.As(err, &noMatchAttestationError) {
			err = s.setWorkloadState(insertCtx, workloadId, sql.WorkloadStateNoAttestation)
			if err != nil {
				return err
			}
			return nil
		} else {
			return err
		}
	}

	err = s.wmgr.InsertJob(insertCtx, workers.UploadAttestationArgs{
		Workload:   workload,
		WorkloadId: workloadId,
		Att:        att,
	})
	if err != nil {
		return fmt.Errorf("InsertJob failed: %v", err)
	}

	s.log.WithField("workload", workload.Name).Debug("attestation job enqueued")
	return nil
}

func (s *Service) UploadAttestation(ctx context.Context, workload *model.Workload, workloadId pgtype.UUID, att *attestation.Attestation) error {
	if att != nil {
		err := s.db.UpdateImage(ctx, sql.UpdateImageParams{
			Name:     workload.ImageName,
			Tag:      workload.ImageTag,
			Metadata: att.Metadata,
		})
		if err != nil {
			return fmt.Errorf("failed to update image metadata: %w", err)
		}

		source := s.src
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

		err = s.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
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

	err := s.setWorkloadState(ctx, workloadId, sql.WorkloadStateUpdated)
	if err != nil {
		return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
	}
	return nil
}

func (s *Service) setWorkloadState(ctx context.Context, id pgtype.UUID, state sql.WorkloadState) error {
	err := s.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: state,
		ID:    id,
	})
	if err != nil {
		return fmt.Errorf("failed to set workload state: %w", err)
	}
	return nil
}

func (s *Service) DeleteWorkload(ctx context.Context, w *model.Workload) error {
	s.log.WithField("workload", w).Debug("deleting workload")
	id, err := s.db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		s.log.WithError(err).Error("Failed to delete workload")
		return err
	}

	refs, err := s.db.ListSourceRefs(ctx, sql.ListSourceRefsParams{
		WorkloadID: id,
		SourceType: s.src.Name(),
	})
	if err != nil {
		s.log.WithError(err).Error("Failed to list source refs")
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
		err = s.src.DeleteWorkload(ctx, ref.SourceID.Bytes, sw)
		if err != nil {
			s.log.WithError(err).Error("Failed to delete workload from source")
			return err
		}
	}
	return nil
}
