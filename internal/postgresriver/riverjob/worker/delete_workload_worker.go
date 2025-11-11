package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type DeleteWorkloadWorker struct {
	Querier   sql.Querier
	Source    sources.Source
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.DeleteWorkloadJob]
}

func (d *DeleteWorkloadWorker) Work(ctx context.Context, j *river.Job[job.DeleteWorkloadJob]) error {
	w := j.Args.Workload
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	d.Log.WithField("workload", w).Debug("deleting workload")
	_, err := d.Querier.DeleteWorkload(ctx, sql.DeleteWorkloadParams{
		Name:         w.Name,
		Cluster:      w.Cluster,
		Namespace:    w.Namespace,
		WorkloadType: string(w.Type),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			rec.Add("delete_workload", "skipped", "workload not found")
			riverjob.RecordOutput(ctx, riverjob.JobStatusSourceRefDeleteSkipped)
			return nil
		}
		rec.Add("delete_workload", "error", err.Error())
		return err
	}

	rec.Add("delete_workload", "ok", "")
	rows, err := d.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
		ImageName: w.ImageName,
		ImageTag:  w.ImageTag,
	})
	if err != nil {
		rec.Add("list_workloads_by_image", "error", err.Error())
		return err
	}

	if len(rows) == 0 {
		rec.Add("image_usage", "unique", "image no longer referenced — queue removal from source")
		err = d.JobClient.AddJob(ctx, &job.RemoveFromSourceJob{
			ImageName: w.ImageName,
			ImageTag:  w.ImageTag,
		})
		if err != nil {
			rec.Add("enqueue_remove", "error", err.Error())
			d.Log.WithError(err).Error("failed to add remove from source job")
			return err
		}
		rec.Add("enqueue_remove", "ok", "")
		rec.Add("finish", "success", "Image removed from source scheduled")
		return nil
	}
	rec.Add("image_usage", "in_use", fmt.Sprintf("still referenced by %d workloads", len(rows)))
	return nil
}
