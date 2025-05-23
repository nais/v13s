package manager

import (
	"context"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindRemoveFromSource = "remove_from_source"
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
			ByPeriod: 1 * time.Minute,
		},
	}
}

type RemoveFromSourceWorker struct {
	db     sql.Querier
	source sources.Source
	log    logrus.FieldLogger
	river.WorkerDefaults[RemoveFromSourceJob]
}

func (r *RemoveFromSourceWorker) Work(ctx context.Context, job *river.Job[RemoveFromSourceJob]) error {
	err := r.db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  job.Args.ImageName,
		ImageTag:   job.Args.ImageTag,
		SourceType: r.source.Name(),
	})
	if err != nil {
		r.log.WithError(err).Error("failed to delete source ref")
		return err
	}
	err = r.source.Delete(ctx, job.Args.ImageName, job.Args.ImageTag)
	if err != nil {
		r.log.WithError(err).Error("failed to delete workload from source")
		return river.JobCancel(err)
	}
	return nil
}
