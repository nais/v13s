package jobs

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindAddWorkload = "add_workload"
)

type AddWorkloadJob struct {
	Workload *model.Workload
}

func (AddWorkloadJob) Kind() string { return KindAddWorkload }

func (a AddWorkloadJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindAddWorkload,
		MaxAttempts: 4,
	}
}

type AddWorkloadWorker struct {
	Querier   sql.Querier
	JobClient job.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[AddWorkloadJob]
}

func (a *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadJob]) error {
	workload := job.Args.Workload

	if err := a.Querier.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: map[string]string{},
	}); err != nil {
		a.Log.WithError(err).Error("Failed to create image")
		return err
	}

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
			RecordOutput(ctx, JobStatusInitializeWorkloadSkipped)
			a.Log.WithField("workload", workload).Debug("workload already initialized, skipping")
			return nil
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			a.Log.WithError(err).Error("failed to get workload")
			return err
		}
	}

	err = a.JobClient.AddJob(ctx, &GetAttestationJob{
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
		WorkloadId:   id,
		WorkloadType: workload.Type,
	})
	if err != nil {
		return err
	}

	err = a.Querier.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateUpdated,
		ID:    id,
	})
	if err != nil {
		return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
	}
	RecordOutput(ctx, JobStatusUpdated)
	return nil
}
