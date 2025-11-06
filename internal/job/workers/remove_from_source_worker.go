package workers

import (
	"context"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type RemoveFromSourceWorker struct {
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[jobs.RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, job *river.Job[jobs.RemoveFromSourceJob]) error {
	ctx, span := otel.Tracer("v13s/remove-from-Source").Start(ctx, "RemoveFromSourceWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
	)

	if err := r.Source.Delete(ctx, job.Args.ImageName, job.Args.ImageTag); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete workload from source")
		r.Log.WithError(err).Error("failed to delete workload from source")
		return jobs.HandleJobErr(err)
	}

	err := r.Querier.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  job.Args.ImageName,
		ImageTag:   job.Args.ImageTag,
		SourceType: r.Source.Name(),
	})
	if err != nil {
		r.Log.WithError(err).Error("failed to delete source ref")
		return jobs.HandleJobErr(err)
	}

	jobs.RecordOutput(ctx, jobs.JobStatusSourceRefDeleted)
	return nil
}
