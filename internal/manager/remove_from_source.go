package manager

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
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
	ImageName string `json:"image_name" river:"unique"`
	ImageTag  string `json:"image_tag" river:"unique"`
}

func (RemoveFromSourceJob) Kind() string { return KindRemoveFromSource }

func (u RemoveFromSourceJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindRemoveFromSource,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: RemoveFromSourceByPeriodMinutes,
		},
		MaxAttempts: 8,
	}
}

type RemoveFromSourceWorker struct {
	db     sql.Querier
	source sources.Source
	log    logrus.FieldLogger
	river.WorkerDefaults[RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, job *river.Job[RemoveFromSourceJob]) error {
	ctx, span := otel.Tracer("v13s/remove-from-source").Start(ctx, "RemoveFromSourceWorker.Work")
	defer span.End()

	span.SetAttributes(
		attribute.String("image.name", job.Args.ImageName),
		attribute.String("image.tag", job.Args.ImageTag),
	)

	// 1. Delete from external source
	if err := r.source.Delete(ctx, job.Args.ImageName, job.Args.ImageTag); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to delete workload from source")
		r.log.WithError(err).Error("failed to delete workload from source")
		return handleJobErr(err)
	}

	// 2. Delete DB ref
	err := r.db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  job.Args.ImageName,
		ImageTag:   job.Args.ImageTag,
		SourceType: r.source.Name(),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			r.log.WithField("image", job.Args.ImageName+":"+job.Args.ImageTag).Debug("DB source ref already removed, nothing to do")
			recordOutput(ctx, JobStatusSourceRefDeleteSkipped)
			return nil
		}
		r.log.WithError(err).Error("failed to delete source ref")
		return handleJobErr(err)
	}

	recordOutput(ctx, JobStatusSourceRefDeleted)
	return nil
}
