package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const (
	KindUploadAttestation            = "upload_attestation"
	UploadAttestationByPeriodMinutes = 2 * time.Minute
)

type UploadAttestationJob struct {
	ImageName   string `river:"unique"`
	ImageTag    string `river:"unique"`
	WorkloadId  pgtype.UUID
	Attestation []byte
}

func (UploadAttestationJob) Kind() string { return KindUploadAttestation }

func (u UploadAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindUploadAttestation,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: UploadAttestationByPeriodMinutes,
		},
		MaxAttempts: 8,
	}
}

type UploadAttestationWorker struct {
	db        sql.Querier
	source    sources.Source
	jobClient job.Client
	log       logrus.FieldLogger
	river.WorkerDefaults[UploadAttestationJob]
}

func (u *UploadAttestationWorker) Work(ctx context.Context, job *river.Job[UploadAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/upload-attestation").Start(ctx, "UploadAttestationWorker")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	sourceRef, err := u.db.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.source.Name(),
	})

	u.log.WithFields(logrus.Fields{
		"image": imageName,
		"tag":   imageTag,
	}).Debugf("uploading attestation")

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("failed to check source ref: %w", err)
	}

	if err == nil {
		// sourceRef exists → check if the project actually exists
		exists, err := u.source.ProjectExists(ctx, sourceRef.ImageName, sourceRef.ImageTag)
		if err != nil {
			return fmt.Errorf("failed to verify project existence: %w", err)
		}
		if exists {
			err = u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
				Name:  imageName,
				Tag:   imageTag,
				State: sql.ImageStateResync,
				ReadyForResyncAt: pgtype.Timestamptz{
					// update immediately, the project exits and a refresh is warranted
					Time:  time.Now(),
					Valid: true,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to update image state: %w", err)
			}

			recordOutput(ctx, JobStatusSourceRefExists)
			return nil
		}

		// project does not exist → delete stale sourceRef
		if err := u.db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
			ImageName:  imageName,
			ImageTag:   imageTag,
			SourceType: u.source.Name(),
		}); err != nil {
			return fmt.Errorf("failed to delete stale sourceRef: %w", err)
		}
		u.log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("deleted stale sourceRef; will attempt to create new project")
	}

	att, err := attestation.Decompress(job.Args.Attestation)
	if err != nil {
		return fmt.Errorf("failed to decompress attestation: %w", err)
	}

	// Upload attestation and create new sourceRef
	uploadRes, upErr := u.source.UploadAttestation(ctx, imageName, imageTag, att.Predicate)
	if upErr != nil {
		span.RecordError(upErr)
		span.SetStatus(codes.Error, "failed to upload attestation to source")
		// TODO: consider creating a table to track sbom upload failures
		// can be used to alert teams of persistent upload failures
		// now we just delete the dangling project and try again
		return handleJobErr(upErr)
	}

	err = u.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID: pgtype.UUID{
			Bytes: uploadRes.AttestationId,
			Valid: true,
		},
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.source.Name(),
	})
	if err != nil {
		return err
	}

	err = u.db.UpdateImage(ctx, sql.UpdateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: att.Metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to set ReadyForResyncAt: %w", err)
	}

	// enqueue finalize job
	err = u.jobClient.AddJob(ctx, &FinalizeAttestationJob{
		ImageName:    imageName,
		ImageTag:     imageTag,
		ProcessToken: uploadRes.ProcessToken,
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue finalize attestation job: %w", err)
	}

	recordOutput(ctx, JobStatusAttestationUploaded)
	return nil
}
