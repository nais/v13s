package sbom

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAttestationWorker struct {
	Manager jobs.WorkloadManager
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.FinalizeAttestationJob]
}

func (f *FinalizeAttestationWorker) Work(ctx context.Context, job *river.Job[types.FinalizeAttestationJob]) error {
	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag

	f.Log.WithFields(logrus.Fields{
		"image": imageName,
		"tag":   imageTag,
	}).Debugf("finalizing attestation")

	inProgress, err := f.Source.IsTaskInProgress(ctx, job.Args.ProcessToken)
	if err != nil {
		return fmt.Errorf("failed to update image state: %w", err)
	}

	if inProgress {
		return fmt.Errorf("attestation task for image %s:%s is still in progress", imageName, imageTag)
	}

	if job.Args.ProcessToken == "" {
		f.Log.Warnf("no process token for image %s:%s, marking as ready for resync", imageName, imageTag)
	}

	// Mark image as ready for resync
	err = f.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateResync,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  time.Now().Add(types.FinalizeAttestationScheduledForResyncMinutes),
			Valid: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update image state: %f", err)
	}

	rows, err := f.Querier.ListUnusedImages(ctx, &imageName)
	if err != nil {
		return fmt.Errorf("failed to list unused images: %w", err)
	}
	for _, row := range rows {
		err = f.Manager.AddJob(ctx, &types.RemoveFromSourceJob{
			ImageName: row.Name,
			ImageTag:  row.Tag,
		})
		if err != nil {
			return fmt.Errorf("failed to enqueue RemoveFromSourceJob for %s:%s: %w",
				row.Name, row.Tag, err)
		}
	}

	output.Record(ctx, output.JobStatusUploadAttestationFinalized)
	return nil
}
