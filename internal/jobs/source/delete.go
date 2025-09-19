package source

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs/output"
	"github.com/nais/v13s/internal/jobs/types"
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
	river.WorkerDefaults[types.RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, job *river.Job[types.RemoveFromSourceJob]) error {
	ctx, span := otel.Tracer("v13s/remove-from-source").Start(ctx, "RemoveFromSourceWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
	)

	r.Log.WithFields(logrus.Fields{
		"image": job.Args.ImageName,
		"tag":   job.Args.ImageTag,
	}).Debugf("Removing image from source and deleting DB reference")

	if err := r.Source.Delete(ctx, job.Args.ImageName, job.Args.ImageTag); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete workload from source")
		r.Log.WithError(err).Error("failed to delete workload from source")
		return output.HandleJobErr(err)
	}

	err := r.Querier.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  job.Args.ImageName,
		ImageTag:   job.Args.ImageTag,
		SourceType: r.Source.Name(),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			r.Log.WithField("image", job.Args.ImageName+":"+job.Args.ImageTag).Debug("DB source ref already removed, nothing to do")
			output.Record(ctx, output.JobStatusSourceRefDeleteSkipped)
			return nil
		}
		r.Log.WithError(err).Error("failed to delete source ref")
		return output.HandleJobErr(err)
	}

	if err := r.Querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  job.Args.ImageName,
		Tag:   job.Args.ImageTag,
		State: sql.ImageStateUnused,
	}); err != nil {
		r.Log.WithError(err).Error("failed to mark image as unused")
	}

	output.Record(ctx, output.JobStatusSourceRefDeleted)
	return nil
}
