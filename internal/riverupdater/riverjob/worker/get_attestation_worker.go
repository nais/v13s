package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/riverqueue/river"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

type GetAttestationWorker struct {
	Querier         sql.Querier
	JobClient       riverjob.Client
	Verifier        attestation.Verifier
	WorkloadCounter metric.Int64UpDownCounter
	Log             logrus.FieldLogger
	river.WorkerDefaults[job.GetAttestationJob]
}

func (g *GetAttestationWorker) Work(ctx context.Context, j *river.Job[job.GetAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/get-attestation").Start(ctx, "GetAttestationWorker.Work")
	defer span.End()

	imageName := j.Args.ImageName
	imageTag := j.Args.ImageTag

	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	span.SetAttributes(
		attribute.String("image.name", imageName),
		attribute.String("image.tag", imageTag),
		attribute.String("workload.id", j.Args.WorkloadId.String()),
	)

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

			rec.Add("get_attestation", "not_found", noMatchAttestationError.Error())

			err = g.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateNoAttestation,
				ID:    j.Args.WorkloadId,
			})
			if err != nil {
				rec.Add("update_state", "error", err.Error())
				return fmt.Errorf("failed to set workload state: %w", err)
			}

			err = g.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				rec.Add("update_state", "error", err.Error())
				return fmt.Errorf("failed to set image state: %w", err)
			}

			if j.Args.WorkloadType == model.WorkloadTypeApp {
				return noMatchAttestationError
			}

			return river.JobCancel(noMatchAttestationError)
		} else if errors.As(err, &unrecoverableError) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			g.Log.WithError(err).Error("unrecoverable error while getting attestation")

			rec.Add("get_attestation", "unrecoverable", unrecoverableError.Error())

			err = g.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateUnrecoverable,
				ID:    j.Args.WorkloadId,
			})
			if err != nil {
				rec.Add("update_state", "error", err.Error())
				return fmt.Errorf("failed to set workload state: %w", err)
			}
			err = g.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				State: sql.ImageStateFailed,
				Name:  imageName,
				Tag:   imageTag,
			})
			if err != nil {
				rec.Add("update_state", "error", err.Error())
				return fmt.Errorf("failed to set image state: %w", err)
			}
			return river.JobCancel(unrecoverableError)
		} else {
			rec.Add("get_attestation", "error", err.Error())
			return riverjob.HandleJobErr(err)
		}
	}
	if att != nil {
		rec.Add("get_attestation", "ok", "attestation present")
		var compressed []byte
		compressed, err = att.Compress()
		if err != nil {
			rec.Add("compress_attestation", "error", err.Error())
			return fmt.Errorf("failed to compress attestation: %w", err)
		}
		err = g.JobClient.AddJob(ctx, &job.UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  j.Args.WorkloadId,
			Attestation: compressed,
		})
		if err != nil {
			rec.Add("enqueue_upload", "error", err.Error())
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		rec.Add("enqueue_upload", "ok", "")
	}
	return rec.Flush(ctx)
}
