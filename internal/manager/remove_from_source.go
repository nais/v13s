package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

const (
	KindRemoveFromSource            = "remove_from_source"
	RemoveFromSourceByPeriodMinutes = 2 * time.Minute
)

type RemoveFromSourceJob struct {
	ImageName      string `json:"image_name" river:"unique"`
	ImageTag       string `json:"image_tag" river:"unique"`
	SourceInstance string `json:"source_instance" river:"unique"`
}

func (RemoveFromSourceJob) Kind() string { return KindRemoveFromSource }

func (u RemoveFromSourceJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindRemoveFromSource,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: RemoveFromSourceByPeriodMinutes,
		},
		MaxAttempts: 6,
	}
}

type RemoveFromSourceWorker struct {
	db      sql.Querier
	sources *sources.Sources
	log     logrus.FieldLogger
	river.WorkerDefaults[RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, job *river.Job[RemoveFromSourceJob]) error {
	ctx, span := otel.Tracer("v13s/remove-from-source").Start(ctx, "RemoveFromSourceWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
	)

	sourceInstance := job.Args.SourceInstance
	source, ok := r.sources.Source(sourceInstance)
	if !ok {
		return fmt.Errorf("source instance %q is not configured", sourceInstance)
	}
	if err := source.Delete(ctx, job.Args.ImageName, job.Args.ImageTag); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete workload from source")
		r.log.WithError(err).Error("failed to delete workload from source")
		return handleJobErr(err)
	}

	err := r.db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:      job.Args.ImageName,
		ImageTag:       job.Args.ImageTag,
		SourceType:     source.Name(),
		SourceInstance: sourceInstance,
	})
	if err != nil {
		r.log.WithError(err).Error("failed to delete source ref")
		return handleJobErr(err)
	}

	recordStatusOutput(ctx, JobStatusSourceRefDeleted)
	return nil
}
