package manager

import (
	"context"

	"github.com/nais/v13s/internal/job"
	"github.com/riverqueue/river"
)

type ctxKey int

const mgrKey ctxKey = iota

func NewContext(ctx context.Context, mgr *WorkloadManager) context.Context {
	return context.WithValue(ctx, mgrKey, mgr)
}

func FromContext(ctx context.Context) *WorkloadManager {
	return ctx.Value(mgrKey).(*WorkloadManager)
}

func JobClient(ctx context.Context) job.Client {
	return FromContext(ctx).jobClient
}

func AddWorker[T river.JobArgs](ctx context.Context, worker river.Worker[T]) {
	job.AddWorker(FromContext(ctx).jobClient, worker)
}
