package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAttestationWorker struct {
	Querier   sql.Querier
	Source    sources.Source
	JobClient job.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[jobs.FinalizeAttestationJob]
}

func (f *FinalizeAttestationWorker) Work(ctx context.Context, job *river.Job[jobs.FinalizeAttestationJob]) error {
	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	// Check if external processing is complete
	inProgress, err := f.Source.IsTaskInProgress(ctx, job.Args.ProcessToken)
	if err != nil {
		return fmt.Errorf("failed to update image state: %w", err)
	}

	if inProgress {
		return fmt.Errorf("attestation task for image %s:%s is still in progress", imageName, imageTag)
	}

	if job.Args.ProcessToken == "" {
		f.Log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("finalizer ran with empty process token, marking for resync anyway")
	}

	// Mark image as ready for resync
	err = f.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateResync,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update image state: %f", err)
	}

	rows, err := f.Querier.ListUnusedSourceRefs(ctx, &imageName)
	if err != nil {
		return fmt.Errorf("failed to list unused images: %w", err)
	}
	for _, row := range rows {
		err = f.JobClient.AddJob(ctx, &jobs.RemoveFromSourceJob{
			ImageName: row.ImageName,
			ImageTag:  row.ImageTag,
		})
		if err != nil {
			return fmt.Errorf("failed to enqueue RemoveFromSourceJob for %s:%s: %w",
				row.ImageName, row.ImageTag, err)
		}
	}

	jobs.RecordOutput(ctx, jobs.JobStatusUploadAttestationFinalized)
	return nil
}
