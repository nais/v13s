package updater

import (
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"time"
)

const (
	KindMarkForResync = "mark_for_resync"
)

type MarkAndResyncJob struct{}

func (MarkAndResyncJob) Kind() string { return KindMarkForResync }

func (j MarkAndResyncJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindMarkForResync,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByPeriod: 5 * time.Minute},
	}
}

type MarkAndResyncWorker struct {
	db        *sql.Queries
	jobClient job.Client
	log       logrus.FieldLogger
}

func (w *MarkAndResyncWorker) Work(ctx context.Context, job *river.Job[MarkAndResyncJob]) error {
	// 1) Mark unused images
	if err := w.db.MarkUnusedImages(ctx, sql.MarkUnusedImagesParams{
		ExcludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateFailed,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{Time: time.Now().Add(-30 * time.Minute), Valid: true},
	}); err != nil {
		return err
	}

	// 2) Mark for resync if stale (12h)
	if err := w.db.MarkImagesForResync(ctx, sql.MarkImagesForResyncParams{
		ThresholdTime: pgtype.Timestamptz{Time: time.Now().Add(-12 * time.Hour), Valid: true},
		ExcludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateUntracked,
			sql.ImageStateFailed,
		},
	}); err != nil {
		return err
	}

	// 3) Enqueue per-image fetchers for images scheduled for sync
	images, err := w.db.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	for _, img := range images {
		err = w.jobClient.AddJob(ctx, &FetchVulnerabilityDataJob{
			ImageName: img.Name,
			ImageTag:  img.Tag,
		})
		if err != nil {
			w.log.WithError(err).Error("failed to enqueue fetch vuln data")
		}
	}
	return nil
}
