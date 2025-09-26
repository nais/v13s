package jobs

import (
	"context"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

type WorkloadManager interface {
	AddJob(ctx context.Context, job river.JobArgs) error
	AddWorkload(ctx context.Context, workload *model.Workload) error
	DeleteWorkload(ctx context.Context, workload *model.Workload) error
	SyncImage(ctx context.Context, imageName, imageTag string) error
}
