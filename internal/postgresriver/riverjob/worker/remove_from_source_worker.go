package worker

import (
	"context"
	"fmt"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
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
	river.WorkerDefaults[job.RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, j *river.Job[job.RemoveFromSourceJob]) error {
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	ctx, span := otel.Tracer("v13s/remove-from-Source").Start(ctx, "RemoveFromSourceWorker.Work")
	defer span.End()

	imageName := j.Args.ImageName
	imageTag := j.Args.ImageTag

	rec.Add("start", "ok", fmt.Sprintf("%s:%s", imageName, imageTag))
	span.SetAttributes(
		attribute.String("image.name", imageName),
		attribute.String("image.tag", imageTag),
	)

	// Delete from source
	if err := r.Source.Delete(ctx, imageName, imageTag); err != nil {
		rec.Add("delete_source", "error", err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete workload from source")
		r.Log.WithError(err).Error("failed to delete workload from source")
		return riverjob.HandleJobErr(err)
	}
	rec.Add("delete_source", "ok", "")

	// Delete local source reference
	rec.Add("delete_source_ref", "start", "")
	err := r.Querier.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: r.Source.Name(),
	})
	if err != nil {
		rec.Add("delete_source_ref", "error", err.Error())
		r.Log.WithError(err).Error("failed to delete source ref")
		return riverjob.HandleJobErr(err)
	}
	rec.Add("delete_source_ref", "ok", "")

	rec.Add("finish", "success", "")
	return nil
}
