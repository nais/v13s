package manager

import (
	"context"
	"fmt"
	"time"

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
		MaxAttempts: 3,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 30 * time.Second,
		},
	}
}

type AddWorkloadWorker struct {
	db        sql.Querier
	log       logrus.FieldLogger
	jobClient job.Client
	river.WorkerDefaults[AddWorkloadJob]
}

func (a *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadJob]) error {
	workload := job.Args.Workload

	if err := a.db.CreateImage(ctx, sql.CreateImageParams{
		Name:     workload.ImageName,
		Tag:      workload.ImageTag,
		Metadata: map[string]string{},
	}); err != nil {
		a.log.WithError(err).Error("Failed to create image")
		return err
	}

	id, err := a.db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
		Name:         workload.Name,
		Cluster:      workload.Cluster,
		Namespace:    workload.Namespace,
		WorkloadType: string(workload.Type),
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
	})
	if err != nil {
		a.log.WithError(err).Error("failed to initialize workload")
		return err
	}

	if !id.Valid {
		recordStatusOutput(ctx, JobStatusInitializeWorkloadSkipped)
		return nil
	}

	image, err := a.db.GetImage(ctx, sql.GetImageParams{
		Name: workload.ImageName,
		Tag:  workload.ImageTag,
	})
	if err != nil {
		a.log.WithError(err).WithFields(logrus.Fields{
			"image": workload.ImageName,
			"tag":   workload.ImageTag,
		}).Warn("failed to get image state; proceeding to enqueue GetAttestationJob")
		image = &sql.Image{}
	}

	if image.State == sql.ImageStateUpdated {
		if err := a.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			State: sql.WorkloadStateUpdated,
			ID:    id,
		}); err != nil {
			return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
		}
		recordStatusOutput(ctx, JobStatusUpdated)
		return nil
	}

	err = a.jobClient.AddJob(ctx, &GetAttestationJob{
		ImageName:    workload.ImageName,
		ImageTag:     workload.ImageTag,
		WorkloadId:   id,
		WorkloadType: workload.Type,
	})
	if err != nil {
		return err
	}

	err = a.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateUpdated,
		ID:    id,
	})
	if err != nil {
		return fmt.Errorf("failed to set workload state %s: %w", sql.WorkloadStateUpdated, err)
	}
	recordStatusOutput(ctx, JobStatusUpdated)
	return nil
}
