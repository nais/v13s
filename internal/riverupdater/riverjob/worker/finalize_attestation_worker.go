package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAttestationWorker struct {
	Querier   sql.Querier
	Source    sources.Source
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.FinalizeAttestationJob]
}

func (f *FinalizeAttestationWorker) Work(ctx context.Context, j *river.Job[job.FinalizeAttestationJob]) error {
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	imageName := j.Args.ImageName
	imageTag := j.Args.ImageTag

	rec.Add("start", "ok", fmt.Sprintf("%s:%s", imageName, imageTag))

	inProgress, err := f.Source.IsTaskInProgress(ctx, j.Args.ProcessToken)
	if err != nil {
		rec.Add("check_in_progress", "error", err.Error())
		return fmt.Errorf("failed to update image state: %w", err)
	}

	if inProgress {
		msg := fmt.Sprintf("attestation task for image %s:%s is still in progress", imageName, imageTag)
		rec.Add("check_in_progress", "pending", msg)
		return errors.New(msg)
	}

	rec.Add("check_in_progress", "complete", "")
	if j.Args.ProcessToken == "" {
		f.Log.WithFields(logrus.Fields{
			"image": imageName,
			"tag":   imageTag,
		}).Warn("finalizer ran with empty process token, marking for resync anyway")
		rec.Add("empty_token", "warn", "token was empty")
	}

	err = f.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateResync,
		ReadyForResyncAt: pgtype.Timestamptz{
			Time:  time.Now().Add(10 * time.Second),
			Valid: true,
		},
	})
	if err != nil {
		rec.Add("update_image_state", "error", err.Error())
		return fmt.Errorf("failed to update image state: %w", err)
	}
	rec.Add("update_image_state", "ok", "")

	rows, err := f.Querier.ListUnusedSourceRefs(ctx, &imageName)
	if err != nil {
		rec.Add("list_unused_refs", "error", err.Error())
		return fmt.Errorf("failed to list unused images: %w", err)
	}
	rec.Add("list_unused_refs", "ok", fmt.Sprintf("count=%d", len(rows)))

	// Enqueue cleanup jobs
	for _, row := range rows {
		key := fmt.Sprintf("%s:%s", row.ImageName, row.ImageTag)
		rec.Add("enqueue_remove_from_source", "start", key)

		err = f.JobClient.AddJob(ctx, &job.RemoveFromSourceJob{
			ImageName: row.ImageName,
			ImageTag:  row.ImageTag,
		})
		if err != nil {
			rec.Add("enqueue_remove_from_source", "error", err.Error())
			return fmt.Errorf("failed to enqueue RemoveFromSourceJob for %s:%s: %w",
				row.ImageName, row.ImageTag, err)
		}

		rec.Add("enqueue_remove_from_source", "ok", key)
	}

	rec.Add("finish", "success", "")
	return nil
}
