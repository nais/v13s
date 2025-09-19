package workload

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type DeleteWorkloadWorker struct {
	Manager jobs.WorkloadManager
	Querier sql.Querier
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.DeleteWorkloadJob]
}

func (d *DeleteWorkloadWorker) Work(ctx context.Context, job *river.Job[types.DeleteWorkloadJob]) error {
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
			output.Record(ctx, output.JobStatusSourceRefDeleteSkipped)
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
		err = d.Manager.AddJob(ctx, &types.RemoveFromSourceJob{
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
		if err != nil {
			d.Log.WithError(err).Error("failed to add remove from source job")
			return err
		}
		output.Record(ctx, output.JobStatusImageRemovedFromSource)
	} else {
		output.Record(ctx, output.JobStatusImageStillInUse)
	}
	return nil
}
