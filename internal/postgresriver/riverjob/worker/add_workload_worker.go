package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type AddWorkloadWorker struct {
	Querier   sql.Querier
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.AddWorkloadJob]
}

func (a *AddWorkloadWorker) Work(ctx context.Context, j *river.Job[job.AddWorkloadJob]) error {
	workload := j.Args.Workload
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	if err := a.Querier.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: map[string]string{},
	}); err != nil {
		rec.Add("create_image", "error", err.Error())
		a.Log.WithError(err).Error("Failed to create image")
		return err
	}

	rec.Add("create_image", "ok", "")
	id, err := a.Querier.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			rec.Add("init_workload", "skipped", "already initialized")
			a.Log.WithField("workload", workload).Debug("workload already initialized, skipping")
			return nil
		}
		rec.Add("init_workload", "error", err.Error())
		a.Log.WithError(err).Error("failed to get workload")
		return err
	}

	rec.Add("init_workload", "ok", fmt.Sprintf("workload_id=%s", id.String()))
	err = a.JobClient.AddJob(ctx, &job.GetAttestationJob{
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
		WorkloadId:   id,
		WorkloadType: workload.Type,
	})
	if err != nil {
		rec.Add("enqueue_get_attestation", "error", err.Error())
		return err
	}

	rec.Add("enqueue_get_attestation", "ok", "")
	err = a.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateUpdated,
		ID:    id,
	})
	if err != nil {
		rec.Add("update_state", "error", err.Error())
		return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
	}

	rec.Add("update_state", "ok", "")
	return rec.Flush(ctx)
}
