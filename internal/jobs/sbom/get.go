package sbom

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

type GetAttestationWorker struct {
	Manager         jobs.WorkloadManager
	Querier         sql.Querier
	Verifier        attestation.Verifier
	WorkloadCounter metric.Int64UpDownCounter
	Log             logrus.FieldLogger
	river.WorkerDefaults[types.GetAttestationJob]
}

func (g *GetAttestationWorker) NextRetry(job *river.Job[types.GetAttestationJob]) time.Time {
	return time.Now().Add(1 * time.Minute)
}

func (g *GetAttestationWorker) Work(ctx context.Context, job *river.Job[types.GetAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/get-attestation").Start(ctx, "GetAttestationWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	g.Log.WithFields(logrus.Fields{
		"image":      imageName,
		"tag":        imageTag,
		"workloadId": job.Args.WorkloadId.String(),
	}).Debugf("getting attestation")

	att, err := g.Verifier.GetAttestation(ctx, fmt.Sprintf("%s:%s", imageName, imageTag))
	g.WorkloadCounter.Add(
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
				g.Log.WithError(err).Error("failed to get attestation")
			}
			err = g.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateNoAttestation,
				ID:    job.Args.WorkloadId,
			})
			if err != nil {
				return fmt.Errorf("failed to set workload state: %w", err)
			}

			err = g.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				return fmt.Errorf("failed to set image state: %w", err)
			}
			output.Record(ctx, output.JobStatusNoAttestation)
			if job.Args.WorkloadType == model.WorkloadTypeApp {
				return noMatchAttestationError
			}
			return river.JobCancel(noMatchAttestationError)
		} else if errors.As(err, &unrecoverableError) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			g.Log.WithError(err).Error("unrecoverable error while getting attestation")
			output.Record(ctx, output.JobStatusUnrecoverable)
			err = g.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateUnrecoverable,
				ID:    job.Args.WorkloadId,
			})
			if err != nil {
				return fmt.Errorf("failed to set workload state: %w", err)
			}
			err = g.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				return fmt.Errorf("failed to set image state: %w", err)
			}
			return river.JobCancel(unrecoverableError)
		} else {
			return output.HandleJobErr(err)
		}
	}
	if att != nil {
		compressed, err := att.Compress()
		if err != nil {
			return fmt.Errorf("failed to compress attestation: %w", err)
		}
		err = g.Manager.AddJob(ctx, &types.UploadAttestationJob{
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
		output.Record(ctx, output.JobStatusAttestationDownloaded)
	}
	return nil
}
