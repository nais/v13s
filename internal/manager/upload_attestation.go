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

	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	span.SetAttributes(
		attribute.String("image.name", imageName),
		attribute.String("image.tag", imageTag),
		attribute.String("workload.id", job.Args.WorkloadId.String()),
	)

	// 1. Check source-ref state and classify the result.
	sourceRefFound, projectExists, err := u.checkSourceRef(ctx, imageName, imageTag)
	if err != nil {
		return err // recoverable; River retries
	}

	sourceRefEvent := classifySourceRefEvent(sourceRefFound, projectExists)
	sourceRefDecision, lookupErr := lookupDecision(sourceRefDecisions, sourceRefEvent, "upload_attestation source_ref")
	if lookupErr != nil {
		return river.JobCancel(lookupErr)
	}

	// 2. Apply source-ref decision side effects.
	if sourceRefDecision.DeleteStale {
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

	if sourceRefDecision.ResyncAndReturn {
		n, err := u.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateResync,
			ReadyForResyncAt: pgtype.Timestamptz{
				Time:  time.Now(),
				Valid: true,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to update image state: %w", err)
		}
		if n == 0 {
			u.log.WithFields(logrus.Fields{"image": imageName, "tag": imageTag}).Warn("UpdateImageState matched no rows, image may already be gone")
		}
		if err := u.db.UpdateWorkloadStateByImage(ctx, sql.UpdateWorkloadStateByImageParams{
			State:     sql.WorkloadStateUpdated,
			ImageName: imageName,
			ImageTag:  imageTag,
		}); err != nil {
			return fmt.Errorf("failed to update workload states for image %s:%s: %w", imageName, imageTag, err)
		}
		recordStructuredOutput(ctx, JobOutput{
			Status:   sourceRefDecision.JobStatus,
			Event:    string(sourceRefEvent),
			Decision: "resync_and_return",
			Details: map[string]string{
				"image": imageName,
				"tag":   imageTag,
			},
		})
		return nil
	}

	// 3. Decompress the attestation payload.
	att, err := attestation.Decompress(job.Args.Attestation)
	if err != nil {
		return fmt.Errorf("failed to decompress attestation: %w", err)
	}

	// 4. Upload attestation to the source.
	// TODO: consider a table to track persistent upload failures for team alerting.
	uploadRes, upErr := u.source.UploadAttestation(ctx, imageName, imageTag, att.Predicate)
	if upErr != nil {
		span.RecordError(upErr)
		span.SetStatus(codes.Error, "failed to upload attestation to source")

		event := classifyUploadAttestationEvent(upErr)
		decision, lookupErr := lookupDecision(uploadAttestationDecisions, event, "upload_attestation")
		if lookupErr != nil {
			return river.JobCancel(lookupErr)
		}

		dbCtx, cancel := context.WithTimeout(ctx, attestationDBTimeout)
		defer cancel()

		if decision.WorkloadState != nil {
			if dbErr := u.db.UpdateWorkloadState(dbCtx, sql.UpdateWorkloadStateParams{
				State: *decision.WorkloadState,
				ID:    job.Args.WorkloadId,
			}); dbErr != nil {
				return fmt.Errorf("failed to set workload state: %w", dbErr)
			}
		}

		if decision.ImageState != nil {
			n, dbErr := u.db.UpdateImageState(dbCtx, sql.UpdateImageStateParams{
				State: *decision.ImageState,
				Name:  imageName,
				Tag:   imageTag,
			})
			if dbErr != nil {
				return fmt.Errorf("failed to set image state: %w", dbErr)
			}
			if n == 0 {
				u.log.WithFields(logrus.Fields{"image": imageName, "tag": imageTag}).Warn("UpdateImageState matched no rows, image may already be gone")
			}
		}

		if decision.JobStatus != "" {
			retry := !decision.CancelJob
			recordStructuredOutput(ctx, JobOutput{
				Status:    decision.JobStatus,
				Event:     string(event),
				Decision:  describeUploadAttestationDecision(decision),
				Retryable: &retry,
				Details: map[string]string{
					"image":         imageName,
					"tag":           imageTag,
					"error_type":    fmt.Sprintf("%T", upErr),
					"unrecoverable": fmt.Sprint(decision.CancelJob),
				},
			})
		}

		if decision.CancelJob {
			u.log.WithError(upErr).WithFields(logrus.Fields{
				"image": imageName,
				"tag":   imageTag,
			}).Warn("upload attestation failed with unrecoverable error; marked workload/image as terminal")
		}

		if decision.CancelJob {
			return river.JobCancel(upErr)
		}
		return upErr
	}

	// 5. Persist upload results.
	if err := u.db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID:   pgtype.UUID{Bytes: uploadRes.AttestationId, Valid: true},
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.source.Name(),
	}); err != nil {
		return err
	}

	if err := u.db.UpdateImage(ctx, sql.UpdateImageParams{
		Name:     imageName,
		Tag:      imageTag,
		Metadata: att.Metadata,
	}); err != nil {
		return fmt.Errorf("failed to update image metadata: %w", err)
	}

	// 6. Enqueue the finalize job.
	if err := u.jobClient.AddJob(ctx, &FinalizeAttestationJob{
		ImageName:    imageName,
		ImageTag:     imageTag,
		ProcessToken: uploadRes.ProcessToken,
	}); err != nil {
		return fmt.Errorf("failed to enqueue finalize attestation job: %w", err)
	}

	recordStructuredOutput(ctx, JobOutput{
		Status:   JobStatusAttestationUploaded,
		Event:    string(sourceRefEvent),
		Decision: "upload_and_enqueue_finalize",
		Details: map[string]string{
			"image":                imageName,
			"tag":                  imageTag,
			"process_token_exists": fmt.Sprint(uploadRes.ProcessToken != ""),
		},
	})
	return nil
}

func describeUploadAttestationDecision(d Decision) string {
	if d.CancelJob {
		return "mark_failed_and_cancel"
	}
	if d.WorkloadState != nil || d.ImageState != nil {
		return "update_state"
	}
	return "retry"
}

// checkSourceRef looks up an existing source ref for the image and checks whether
// its upstream project is still alive. Returns (found, projectExists, error).
func (u *UploadAttestationWorker) checkSourceRef(ctx context.Context, imageName, imageTag string) (found bool, projectExists bool, err error) {
	sourceRef, err := u.db.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: u.source.Name(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("failed to check source ref: %w", err)
	}

	exists, err := u.source.ProjectExists(ctx, sourceRef.ImageName, sourceRef.ImageTag)
	if err != nil {
		return true, false, fmt.Errorf("failed to verify project existence: %w", err)
	}
	return true, exists, nil
}
