package manager

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
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
	}
}

type DeleteWorkloadWorker struct {
	db     sql.Querier
	source sources.Source
	log    logrus.FieldLogger
	river.WorkerDefaults[DeleteWorkloadJob]
	jobClient job.Client
}

func (d *DeleteWorkloadWorker) Work(ctx context.Context, job *river.Job[DeleteWorkloadJob]) error {
	w := job.Args.Workload
	d.log.WithField("workload", w).Debug("deleting workload")
	_, err := d.db.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			recordOutput(ctx, JobStatusSkipped)
			return nil
		}
		return err
	}

	rows, err := d.db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: w.ImageName,
		ImageTag:  w.ImageTag,
	})
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		err = d.jobClient.AddJob(ctx, &RemoveFromSourceJob{
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
		if err != nil {
			d.log.WithError(err).Error("failed to add remove from source job")
			return err
		}
		recordOutput(ctx, JobStatusImageRemovedFromSource)
	} else {
		recordOutput(ctx, JobStatusImageStillInUse)
	}
	return nil
}
