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
	KindUploadAttestation = "upload_attestation"
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
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 4,
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
	att, err := attestation.Decompress(job.Args.Attestation)
	if err != nil {
		return fmt.Errorf("failed to decompress attestation: %w", err)
	}

	err = u.db.UpdateImage(ctx, sql.UpdateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: att.Metadata,
	})
	if err != nil {
		return fmt.Errorf("failed to update image metadata: %w", err)
	}

	// TODO: handle concurrency locking
	_, err = u.db.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.source.Name(),
	})
	if err == nil {
		recordOutput(ctx, JobStatusSourceRefExists)
	}

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			id, err := u.source.UploadAttestation(ctx, imageName, imageTag, att.Predicate)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to upload attestation to source")
				return handleJobErr(err)
			}

			err = u.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
				SourceID: pgtype.UUID{
					Bytes: id,
					Valid: true,
				},
				ImageName:  imageName,
				ImageTag:   imageTag,
				SourceType: u.source.Name(),
			})
			if err != nil {
				return err
			}
			recordOutput(ctx, JobStatusAttestationUploaded)
		}
	}

	rows, err := u.db.ListUnusedImages(ctx, &imageName)
	if err != nil {
		return err
	}
	for _, row := range rows {
		err = u.jobClient.AddJob(ctx, &RemoveFromSourceJob{
			ImageName: row.Name,
			ImageTag:  row.Tag,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
