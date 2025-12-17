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
	KindGetAttestation = "get_attestation"
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

	if err != nil {
		var noMatchAttestationError *cosign.ErrNoMatchingAttestations
		var unrecoverableError model.UnrecoverableError
		// TODO: handle no attestation found vs error in verifying
		if errors.As(err, &noMatchAttestationError) {
			if err.Error() != "no matching attestations: " {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				g.log.WithError(err).Error("failed to get attestation")
			}
			// TODO: handle errors
			err = g.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateNoAttestation,
				ID:    job.Args.WorkloadId,
			})
			if err != nil {
				return fmt.Errorf("failed to set workload state: %w", err)
			}

			err = g.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				return fmt.Errorf("failed to set image state: %w", err)
			}
			recordOutput(ctx, JobStatusNoAttestation)
			if job.Args.WorkloadType == model.WorkloadTypeApp {
				return noMatchAttestationError
			}
			return river.JobCancel(noMatchAttestationError)
		} else if errors.As(err, &unrecoverableError) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			g.log.WithError(err).Error("unrecoverable error while getting attestation")
			recordOutput(ctx, JobStatusUnrecoverable)
			err = g.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateUnrecoverable,
				ID:    job.Args.WorkloadId,
			})
			if err != nil {
				return fmt.Errorf("failed to set workload state: %w", err)
			}
			err = g.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				return fmt.Errorf("failed to set image state: %w", err)
			}
			return river.JobCancel(unrecoverableError)
		} else {
			return handleJobErr(err)
		}
	}
	if att != nil {
		compressed, err := att.Compress()
		if err != nil {
			return fmt.Errorf("failed to compress attestation: %w", err)
		}
		err = g.jobClient.AddJob(ctx, &UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  job.Args.WorkloadId,
			Attestation: compressed,
		})
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		recordOutput(ctx, JobStatusAttestationDownloaded)
	}
	return nil
}
