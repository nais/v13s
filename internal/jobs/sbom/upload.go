package sbom

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type UploadAttestationWorker struct {
	Manager jobs.WorkloadManager
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.UploadAttestationJob]
}

func (u *UploadAttestationWorker) Work(ctx context.Context, job *river.Job[types.UploadAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/upload-attestation").Start(ctx, "UploadAttestationWorker")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	sourceRef, err := u.Querier.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.Source.Name(),
	})

	u.Log.WithFields(logrus.Fields{
		"image": imageName,
		"tag":   imageTag,
	}).Debugf("uploading attestation")

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("failed to check Verifier ref: %w", err)
	}

	if err == nil {
		// sourceRef exists → check if the project actually exists
		exists, ExistErr := u.Source.ProjectExists(ctx, sourceRef.ImageName, sourceRef.ImageTag)
		if ExistErr != nil {
			return fmt.Errorf("failed to verify project existence: %w", err)
		}
		if exists {
			err = u.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
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

			output.Record(ctx, output.JobStatusSourceRefExists)
			return nil
		}

		// project does not exist → delete stale sourceRef
		if err = u.Querier.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
			ImageName:  imageName,
			ImageTag:   imageTag,
			SourceType: u.Source.Name(),
		}); err != nil {
			return fmt.Errorf("failed to delete stale sourceRef: %w", err)
		}
		u.Log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("deleted stale sourceRef; will attempt to create new project")
	}

	att, err := attestation.Decompress(job.Args.Attestation)
	if err != nil {
		return fmt.Errorf("failed to decompress attestation: %w", err)
	}

	// Upload attestation and create new sourceRef
	uploadRes, upErr := u.Source.UploadAttestation(ctx, imageName, imageTag, att.Predicate)
	if upErr != nil {
		span.RecordError(upErr)
		span.SetStatus(codes.Error, "failed to upload attestation to Verifier")
		// TODO: consider creating a table to track sbom upload failures
		// can be used to alert teams of persistent upload failures
		// now we just delete the dangling project and try again
		return output.HandleJobErr(upErr)
	}

	err = u.Querier.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID: pgtype.UUID{
			Bytes: uploadRes.AttestationId,
			Valid: true,
		},
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.Source.Name(),
	})
	if err != nil {
		return err
	}

	err = u.Querier.UpdateImage(ctx, sql.UpdateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: att.Metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to set ReadyForResyncAt: %w", err)
	}

	// enqueue finalize job
	err = u.Manager.AddJob(ctx, &types.FinalizeAttestationJob{
		ImageName:    imageName,
		ImageTag:     imageTag,
		ProcessToken: uploadRes.ProcessToken,
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue finalize attestation job: %w", err)
	}

	output.Record(ctx, output.JobStatusAttestationUploaded)
	return nil
}
