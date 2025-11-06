package workers

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type DeleteWorkloadWorker struct {
	Querier   sql.Querier
	Source    sources.Source
	JobClient job.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[jobs.DeleteWorkloadJob]
}

func (d *DeleteWorkloadWorker) Work(ctx context.Context, job *river.Job[jobs.DeleteWorkloadJob]) error {
	w := job.Args.Workload
	d.Log.WithField("workload", w).Debug("deleting workload")
	_, err := d.Querier.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jobs.RecordOutput(ctx, jobs.JobStatusSourceRefDeleteSkipped)
			return nil
		}
		return err
	}

	rows, err := d.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: w.ImageName,
		ImageTag:  w.ImageTag,
	})
	if err != nil {
		return err
	}

	if len(rows) == 0 {
		err = d.JobClient.AddJob(ctx, &jobs.RemoveFromSourceJob{
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
		if err != nil {
			d.Log.WithError(err).Error("failed to add remove from source job")
			return err
		}
		jobs.RecordOutput(ctx, jobs.JobStatusImageRemovedFromSource)
	} else {
		jobs.RecordOutput(ctx, jobs.JobStatusImageStillInUse)
	}
	return nil
}
