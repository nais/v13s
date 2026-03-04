package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

const (
	KindGetAttestation   = "get_attestation"
	attestationDBTimeout = 10 * time.Second
)

type GetAttestationJob struct {
	ImageName    string
	ImageTag     string
	WorkloadId   pgtype.UUID
	WorkloadType model.WorkloadType
}

func (GetAttestationJob) Kind() string { return KindGetAttestation }

func (g GetAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindGetAttestation,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 4,
	}
}

type GetAttestationWorker struct {
	db              sql.Querier
	jobClient       job.Client
	verifier        attestation.Verifier
	workloadCounter metric.Int64UpDownCounter
	log             logrus.FieldLogger
	river.WorkerDefaults[GetAttestationJob]
}

func (g *GetAttestationWorker) NextRetry(job *river.Job[GetAttestationJob]) time.Time {
	return time.Now().Add(1 * time.Minute)
}

func (g *GetAttestationWorker) Work(ctx context.Context, job *river.Job[GetAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/get-attestation").Start(ctx, "GetAttestationWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag
	att, err := g.verifier.GetAttestation(ctx, fmt.Sprintf("%s:%s", imageName, imageTag))
	g.workloadCounter.Add(
		ctx,
		1,
		metric.WithAttributes(
			attribute.String("hasAttestation", fmt.Sprint(att != nil)),
		))

	runDB := func(fn func(dbCtx context.Context) error) error {
		dbCtx, cancel := context.WithTimeout(ctx, attestationDBTimeout)
		defer cancel()
		return fn(dbCtx)
	}

	if err != nil {
		var noMatchAttestationError *cosign.ErrNoMatchingAttestations
		var unrecoverableError model.UnrecoverableError

		if errors.As(err, &noMatchAttestationError) {
			// No matching attestations is a terminal but expected state for many images.
			g.log.WithError(err).WithFields(logrus.Fields{
				"image":         imageName,
				"tag":           imageTag,
				"workloadId":    job.Args.WorkloadId,
				"workload_type": job.Args.WorkloadType,
			}).Info("no attestations found for workload image")

			if dbErr := runDB(func(dbCtx context.Context) error {
				return g.db.UpdateWorkloadState(dbCtx, sql.UpdateWorkloadStateParams{
					State: sql.WorkloadStateNoAttestation,
					ID:    job.Args.WorkloadId,
				})
			}); dbErr != nil {
				return fmt.Errorf("failed to set workload state: %w", dbErr)
			}

			if dbErr := runDB(func(dbCtx context.Context) error {
				return g.db.UpdateImageState(dbCtx, sql.UpdateImageStateParams{
					State: sql.ImageStateFailed,
					Name:  imageName,
					Tag:   imageTag,
				})
			}); dbErr != nil {
				return fmt.Errorf("failed to set image state: %w", dbErr)
			}

			recordOutput(ctx, JobStatusNoAttestation)
			span.SetStatus(codes.Ok, "no attestation found")
			// Always cancel the job so River does not keep retrying this expected condition.
			return river.JobCancel(noMatchAttestationError)
		} else if errors.As(err, &unrecoverableError) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			g.log.WithFields(
				logrus.Fields{
					"image":      imageName,
					"tag":        imageTag,
					"workloadId": job.Args.WorkloadId,
				},
			).Info("marking workload and image as unrecoverable due to unrecoverable error from attestation source")
			recordOutput(ctx, JobStatusUnrecoverable)

			if dbErr := runDB(func(dbCtx context.Context) error {
				return g.db.UpdateWorkloadState(dbCtx, sql.UpdateWorkloadStateParams{
					State: sql.WorkloadStateUnrecoverable,
					ID:    job.Args.WorkloadId,
				})
			}); dbErr != nil {
				return fmt.Errorf("failed to set workload state: %w", dbErr)
			}
			if dbErr := runDB(func(dbCtx context.Context) error {
				return g.db.UpdateImageState(dbCtx, sql.UpdateImageStateParams{
					State: sql.ImageStateFailed,
					Name:  imageName,
					Tag:   imageTag,
				})
			}); dbErr != nil {
				return fmt.Errorf("failed to set image state: %w", dbErr)
			}
			return river.JobCancel(unrecoverableError)
		}

		return handleJobErr(err)
	}
	if att != nil {
		compressed, err := att.Compress()
		if err != nil {
			return fmt.Errorf("failed to compress attestation: %w", err)
		}
		if err := g.jobClient.AddJob(ctx, &UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  job.Args.WorkloadId,
			Attestation: compressed,
		}); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		recordOutput(ctx, JobStatusAttestationDownloaded)
		g.log.WithFields(logrus.Fields{
			"image":         imageName,
			"tag":           imageTag,
			"workloadId":    job.Args.WorkloadId,
			"workload_type": job.Args.WorkloadType,
		}).Debug("attestation downloaded and upload_attestation job enqueued")
	}

	span.SetStatus(codes.Ok, "attestation processing complete")
	return nil
}
