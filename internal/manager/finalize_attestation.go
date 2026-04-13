package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindFinalizeAttestation   = "finalize_attestation"
	FinalizeAttestationDelay  = 5 * time.Second
	FinalizeAttestationResync = 10 * time.Second
)

type FinalizeAttestationJob struct {
	ImageName    string `river:"unique"`
	ImageTag     string `river:"unique"`
	ProcessToken string
}

func (FinalizeAttestationJob) Kind() string { return KindFinalizeAttestation }

func (f FinalizeAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinalizeAttestation,
		ScheduledAt: time.Now().Add(FinalizeAttestationDelay),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 15,
	}
}

type FinalizeAttestationWorker struct {
	db        sql.Querier
	source    sources.Source
	jobClient job.Client
	log       logrus.FieldLogger
	river.WorkerDefaults[FinalizeAttestationJob]
}

func (f *FinalizeAttestationWorker) Work(ctx context.Context, job *river.Job[FinalizeAttestationJob]) error {
	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	processToken := job.Args.ProcessToken

	if processToken == "" {
		f.log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("finalizer ran with empty process token, marking for resync anyway")
	}

	// 1. Check whether external processing is complete.
	// Empty tokens are treated as complete to avoid source-specific parse errors
	// (e.g. dependencytrack expects UUID process tokens).
	event := EventTaskComplete
	if processToken != "" {
		inProgress, err := f.source.IsTaskInProgress(ctx, processToken)
		if err != nil {
			return fmt.Errorf("failed to check task progress: %w", err)
		}
		event = classifyFinalizeEvent(inProgress)
	}

	// 2. Translate the progress check into a decision.
	decision, lookupErr := lookupDecision(finalizeDecisions, event, "finalize_attestation")
	if lookupErr != nil {
		return river.JobCancel(lookupErr)
	}

	// 3. Still running → return error so River retries on its schedule.
	if decision.RetryLater {
		recordStructuredOutput(ctx, JobOutput{
			Event:    string(event),
			Decision: "retry_later",
			Details: map[string]string{
				"image": imageName,
				"tag":   imageTag,
			},
		})
		return fmt.Errorf("attestation task for image %s:%s is still in progress", imageName, imageTag)
	}

	// 4. Mark image as ready for resync.
	if decision.MarkResync {
		if err := f.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateResync,
			ReadyForResyncAt: pgtype.Timestamptz{
				Time:  time.Now().Add(FinalizeAttestationResync),
				Valid: true,
			},
		}); err != nil {
			return fmt.Errorf("failed to update image state: %w", err)
		}
	}

	// 5. Enqueue cleanup for unused source refs.
	removalCount := 0
	if decision.EnqueueRemovals {
		rows, err := f.db.ListUnusedSourceRefs(ctx, &imageName)
		if err != nil {
			return fmt.Errorf("failed to list unused images: %w", err)
		}
		removalCount = len(rows)
		for _, row := range rows {
			if err := f.jobClient.AddJob(ctx, &RemoveFromSourceJob{
				ImageName: row.ImageName,
				ImageTag:  row.ImageTag,
			}); err != nil {
				return fmt.Errorf("failed to enqueue RemoveFromSourceJob for %s:%s: %w",
					row.ImageName, row.ImageTag, err)
			}
		}
	}

	// 6. Record River job output.
	if decision.JobStatus != "" {
		recordStructuredOutput(ctx, JobOutput{
			Status:   decision.JobStatus,
			Event:    string(event),
			Decision: "mark_resync_and_cleanup",
			Details: map[string]string{
				"image":             imageName,
				"tag":               imageTag,
				"removals_enqueued": fmt.Sprint(removalCount),
			},
		})
	}

	return nil
}
