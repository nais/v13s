package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type UploadAttestationWorker struct {
	Querier   sql.Querier
	Source    sources.Source
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.UploadAttestationJob]
}

func (u *UploadAttestationWorker) Work(ctx context.Context, j *river.Job[job.UploadAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/upload-attestation").Start(ctx, "UploadAttestationWorker")
	defer span.End()

	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	imageName := j.Args.ImageName
	imageTag := j.Args.ImageTag

	rec.Add("start", "begin", imageName)

	span.SetAttributes(
		attribute.String("image.name", imageName),
		attribute.String("image.tag", imageTag),
		attribute.String("workload.id", j.Args.WorkloadId.String()),
	)

	sourceRef, err := u.Querier.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.Source.Name(),
	})

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		rec.Add("get_source_ref", "error", err.Error())
		return fmt.Errorf("failed to check source ref: %w", err)
	}

	if err == nil {
		// sourceRef exists → check if the project actually exists
		rec.Add("get_source_ref", "found", fmt.Sprintf("sourceID=%s", sourceRef.SourceID.String()))
		exists, err := u.Source.ProjectExists(ctx, sourceRef.ImageName, sourceRef.ImageTag)
		if err != nil {
			rec.Add("project_exists", "error", err.Error())
			return fmt.Errorf("failed to verify project existence: %w", err)
		}
		if exists {
			rec.Add("project_exists", "ok", "project exists, marking image resync")
			err = u.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				Name:  imageName,
				Tag:   imageTag,
				State: sql.ImageStateResync,
				ReadyForResyncAt: pgtype.Timestamptz{
					Time:  time.Now(),
					Valid: true,
				},
			})
			if err != nil {
				rec.Add("update_image_state", "error", err.Error())
				return fmt.Errorf("failed to update image state: %w", err)
			}

			rec.Add("finish", "success", "existing sourceRef kept — resync scheduled")
			return nil
		}

		// project does not exist → delete stale sourceRef
		rec.Add("project_exists", "stale", "project missing upstream — deleting sourceRef")
		if err := u.Querier.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
			ImageName:  imageName,
			ImageTag:   imageTag,
			SourceType: u.Source.Name(),
		}); err != nil {
			rec.Add("delete_source_ref", "error", err.Error())
			return fmt.Errorf("failed to delete stale sourceRef: %w", err)
		}
		u.Log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("deleted stale sourceRef; will attempt to create new project")
	}

	rec.Add("delete_source_ref", "ok", "")
	att, err := attestation.Decompress(j.Args.Attestation)
	if err != nil {
		rec.Add("decompress_attestation", "error", err.Error())
		return fmt.Errorf("failed to decompress attestation: %w", err)
	}

	rec.Add("decompress_attestation", "ok", "")
	// Upload attestation and create new sourceRef
	uploadRes, upErr := u.Source.UploadAttestation(ctx, imageName, imageTag, att.Predicate)
	if upErr != nil {
		span.RecordError(upErr)
		span.SetStatus(codes.Error, "failed to upload attestation to source")
		// TODO: consider creating a table to track sbom upload failures
		// can be used to alert teams of persistent upload failures
		// now we just delete the dangling project and try again
		rec.Add("upload_attestation", "error", upErr.Error())
		return riverjob.HandleJobErr(upErr)
	}

	rec.Add("upload_attestation", "ok", fmt.Sprintf("attestationID=%x", uploadRes.AttestationId))
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
		rec.Add("create_source_ref", "error", err.Error())
		return err
	}

	rec.Add("create_source_ref", "ok", "")
	err = u.Querier.UpdateImage(ctx, sql.UpdateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: att.Metadata,
	})
	if err != nil {
		rec.Add("update_image", "error", err.Error())
		return fmt.Errorf("failed to set ReadyForResyncAt: %w", err)
	}

	rec.Add("update_image", "ok", "")

	// enqueue finalize job
	err = u.JobClient.AddJob(ctx, &job.FinalizeAttestationJob{
		ImageName:    imageName,
		ImageTag:     imageTag,
		ProcessToken: uploadRes.ProcessToken,
	})
	if err != nil {
		rec.Add("enqueue_finalize", "error", err.Error())
		return fmt.Errorf("failed to enqueue finalize attestation job: %w", err)
	}

	rec.Add("finish", "success", "")
	return nil
}
