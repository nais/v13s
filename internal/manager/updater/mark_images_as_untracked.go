package updater

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const KindMarkImagesAsUntracked = "mark_images_as_untracked"

type MarkImagesAsUntrackedJob struct{}

func (MarkImagesAsUntrackedJob) Kind() string { return KindMarkImagesAsUntracked }

func (MarkImagesAsUntrackedJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindMarkImagesAsUntracked,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByPeriod: 5 * time.Minute},
	}
}

type MarkImagesAsUntrackedWorker struct {
	db  sql.Querier
	log logrus.FieldLogger
	river.WorkerDefaults[MarkImagesAsUntrackedJob]
}

func (w *MarkImagesAsUntrackedWorker) Work(ctx context.Context, job *river.Job[MarkImagesAsUntrackedJob]) error {
	return w.db.MarkImagesAsUntracked(ctx, sql.MarkImagesAsUntrackedParams{
		IncludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{Time: time.Now().Add(-30 * time.Minute), Valid: true},
	})
}
