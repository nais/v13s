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
	KindFinalizeAttestation                = "finalize_attestation"
	FinalizeAttestationScheduledForResync  = 10 * time.Second
	FinalizeAttestationScheduledWaitSecond = 10 * time.Second
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
		ScheduledAt: time.Now().Add(FinalizeAttestationScheduledWaitSecond),
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

	// Check if external processing is complete
	inProgress, err := f.source.IsTaskInProgress(ctx, job.Args.ProcessToken)
	if err != nil {
		return fmt.Errorf("failed to update image state: %w", err)
	}

	if inProgress {
		return fmt.Errorf("attestation task for image %s:%s is still in progress", imageName, imageTag)
	}

	if job.Args.ProcessToken == "" {
		f.log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("finalizer ran with empty process token, marking for resync anyway")
	}

	// Mark image as ready for resync
	err = f.db.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateResync,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  time.Now().Add(FinalizeAttestationScheduledForResync),
			Valid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update image state: %f", err)
	}

	rows, err := f.db.ListUnusedSourceRefs(ctx, &imageName)
	if err != nil {
		return fmt.Errorf("failed to list unused images: %w", err)
	}
	for _, row := range rows {
		err = f.jobClient.AddJob(ctx, &RemoveFromSourceJob{
			ImageName: row.ImageName,
			ImageTag:  row.ImageTag,
		})
		if err != nil {
			return fmt.Errorf("failed to enqueue RemoveFromSourceJob for %s:%s: %w",
				row.ImageName, row.ImageTag, err)
		}
	}

	recordOutput(ctx, JobStatusUploadAttestationFinalized)
	return nil
}
