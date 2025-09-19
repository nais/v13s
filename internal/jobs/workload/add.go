package workload

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type AddWorkloadWorker struct {
	Manager jobs.WorkloadManager
	Querier sql.Querier
	Log     logrus.FieldLogger
	river.WorkerDefaults[types.AddWorkloadJob]
}

func (a *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[types.AddWorkloadJob]) error {
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
			output.Record(ctx, output.JobStatusInitializeWorkloadSkipped)
			a.Log.WithField("workload", workload).Debug("workload already initialized, skipping")
			return nil
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			a.Log.WithError(err).Error("failed to get workload")
			return err
		}
	}

	err = a.Manager.AddJob(ctx, &types.GetAttestationJob{
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
	output.Record(ctx, output.JobStatusUpdated)
	return nil
}
