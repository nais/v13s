package manager

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindDeleteWorkload = "delete_workload"
)

type DeleteWorkloadJob struct {
	Workload *model.Workload
}

func (DeleteWorkloadJob) Kind() string { return KindDeleteWorkload }

func (u DeleteWorkloadJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindDeleteWorkload,
		MaxAttempts: 4,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
	}
}

type DeleteWorkloadWorker struct {
	db  sql.Querier
	log logrus.FieldLogger
	river.WorkerDefaults[DeleteWorkloadJob]
	jobClient job.Client
}

func (d *DeleteWorkloadWorker) Work(ctx context.Context, job *river.Job[DeleteWorkloadJob]) error {
	workload := job.Args.Workload
	d.log.WithField("workload", workload).Debug("deleting workload")

	// Remove the workload row first.
	_, err := d.db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			recordStatusOutput(ctx, JobStatusSourceRefDeleteSkipped)
			return nil
		}
		return err
	}

	// If this image is no longer referenced by any workload, schedule source cleanup.
	rows, err := d.db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: workload.ImageName,
		ImageTag:  workload.ImageTag,
	})
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		err = d.jobClient.AddJob(ctx, &RemoveFromSourceJob{
			ImageName: workload.ImageName,
			ImageTag:  workload.ImageTag,
		})
		if err != nil {
			d.log.WithError(err).Error("failed to add remove from source job")
			return err
		}
		recordStatusOutput(ctx, JobStatusImageRemovedFromSource)
	} else {
		recordStatusOutput(ctx, JobStatusImageStillInUse)
	}
	return nil
}
