package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
)

const (
	attestationDBTimeout = 10 * time.Second
)

type GetAttestationJob struct {
	ImageName    string
	ImageTag     string
	WorkloadId   pgtype.UUID
	WorkloadType model.WorkloadType
}

func (GetAttestationJob) Kind() string { return model.JobKindGetAttestation }

func (g GetAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: model.JobKindGetAttestation,
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

func (g *GetAttestationWorker) NextRetry(_ *river.Job[GetAttestationJob]) time.Time {
	return time.Now().Add(1 * time.Minute)
}

func (g *GetAttestationWorker) Work(ctx context.Context, job *river.Job[GetAttestationJob]) error {
	ctx, span := otel.Tracer("v13s/get-attestation").Start(ctx, "GetAttestationWorker.Work")
	defer span.End()

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	span.SetAttributes(
		attribute.String("image.name", imageName),
		attribute.String("image.tag", imageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	logFields := logrus.Fields{
		"image":         imageName,
		"tag":           imageTag,
		"workloadId":    job.Args.WorkloadId,
		"workload_type": job.Args.WorkloadType,
	}

	// 1. Call external verifier.
	att, err := g.verifier.GetAttestation(ctx, fmt.Sprintf("%s:%s", imageName, imageTag))
	g.workloadCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("hasAttestation", fmt.Sprint(att != nil)),
	))

	// 2. Classify the verifier result into a domain event.
	event := classifyGetAttestationEvent(att, err)

	// 3. Translate the event into a decision.
	decision, lookupErr := lookupDecision(getAttestationDecisions, event, "get_attestation")
	if lookupErr != nil {
		return river.JobCancel(lookupErr)
	}

	// 4. Log event-specific context.
	switch event {
	case EventNoMatchingAttestations:
		g.log.WithError(err).WithFields(logFields).Info("no attestations found for workload image")
	case EventUnrecoverable:
		g.log.WithFields(logFields).Info("marking workload and image as unrecoverable due to unrecoverable error from attestation source")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	// 5. Apply DB state changes in a single timeout context.
	dbCtx, cancel := context.WithTimeout(ctx, attestationDBTimeout)
	defer cancel()

	if decision.WorkloadState != nil {
		if dbErr := g.db.UpdateWorkloadState(dbCtx, sql.UpdateWorkloadStateParams{
			State: *decision.WorkloadState,
			ID:    job.Args.WorkloadId,
		}); dbErr != nil {
			return fmt.Errorf("failed to set workload state: %w", dbErr)
		}
	}

	if decision.ImageState != nil {
		// Only persist a terminal image state (failed) on the final attempt.
		// On intermediate retries, leave the image state unchanged so a
		// previously-successful resync or updated state is not clobbered.
		isFinalAttempt := job.Attempt >= job.MaxAttempts
		if *decision.ImageState != sql.ImageStateFailed || isFinalAttempt {
			n, dbErr := g.db.UpdateImageState(dbCtx, sql.UpdateImageStateParams{
				State: *decision.ImageState,
				Name:  imageName,
				Tag:   imageTag,
			})
			if dbErr != nil {
				return fmt.Errorf("failed to set image state: %w", dbErr)
			}
			if n == 0 {
				g.log.WithFields(logFields).Warn("UpdateImageState matched no rows, image may already be gone")
			}
		}
	}

	// 6. Enqueue the next River job if the decision requires it.
	if decision.EnqueueUpload && att != nil {
		compressed, compErr := att.Compress()
		if compErr != nil {
			return fmt.Errorf("failed to compress attestation: %w", compErr)
		}
		if enqErr := g.jobClient.AddJob(ctx, &UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  job.Args.WorkloadId,
			Attestation: compressed,
		}); enqErr != nil {
			span.RecordError(enqErr)
			span.SetStatus(codes.Error, enqErr.Error())
			return enqErr
		}
		g.log.WithFields(logFields).Debug("attestation downloaded and upload_attestation job enqueued")
	}

	// 7. Record River job output with decision trace.
	if decision.JobStatus != "" {
		retry := !decision.CancelJob
		recordStructuredOutput(ctx, JobOutput{
			Status:    decision.JobStatus,
			Event:     string(event),
			Decision:  describeGetAttestationDecision(decision),
			Retryable: &retry,
			Details: map[string]string{
				"image":   imageName,
				"tag":     imageTag,
				"enqueue": fmt.Sprint(decision.EnqueueUpload),
			},
		})
	}

	// 8. Cancel River retries for terminal events; let River retry for recoverable errors.
	if decision.CancelJob {
		return river.JobCancel(err)
	}

	span.SetStatus(codes.Ok, "attestation processing complete")
	return err // nil on success; non-nil recoverable error triggers River retry
}

func describeGetAttestationDecision(d Decision) string {
	if d.EnqueueUpload {
		return "enqueue_upload"
	}
	if d.CancelJob {
		return "cancel"
	}
	if d.WorkloadState != nil || d.ImageState != nil {
		return "update_state"
	}
	return "retry"
}
