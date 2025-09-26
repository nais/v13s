package updater

import (
	"context"
	"time"

	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/jobs"
	"github.com/sirupsen/logrus"
)

const (
	MarkUntrackedCronInterval                          = "*/20 * * * *" // every 20 minutes
	MarkUnusedCronInterval                             = "*/30 * * * *" // every 30 minutes
	RefreshVulnerabilitySummaryCronDailyView           = "30 4 * * *"   // every day at 6:30 AM CEST
	RefreshWorkloadVulnerabilityLifetimesCronDailyView = "0 5 * * *"    // every day at 7:00 AM CEST (30 min later)
	ImageMarkAge                                       = 30 * time.Minute
	ResyncImagesOlderThanMinutesDefault                = 30 * 12 * time.Minute // 30 * 12 minutes = 6 hours, default for resyncing images
)

type Updater struct {
	querier                      *sql.Queries
	resyncImagesOlderThanMinutes time.Duration
	updateSchedule               ScheduleConfig
	log                          *logrus.Entry
	mgr                          jobs.WorkloadManager
}

func NewUpdater(mgr jobs.WorkloadManager, pool *pgxpool.Pool, schedule ScheduleConfig, log *log.Entry) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	return &Updater{
		mgr:                          mgr,
		querier:                      sql.New(pool),
		resyncImagesOlderThanMinutes: ResyncImagesOlderThanMinutesDefault,
		updateSchedule:               schedule,
		log:                          log,
	}
}

// Run TODO: create a state/log table and log errors? maybe successfull and failed runs?
func (u *Updater) Run(ctx context.Context) {
	go runScheduled(ctx, u.updateSchedule, "mark and resync images and sync workload vulnerabilities", u.log, func() {
		if err := u.MarkForResync(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images for resync")
			return
		}
		if err := u.ResyncImageVulnerabilities(ctx); err != nil {
			u.log.WithError(err).Error("Failed to resync images")
		}
	})

	go runScheduled(ctx, ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUnusedCronInterval}, "mark unused images", u.log, func() {
		if err := u.MarkUnusedImages(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark unused images")
		}
	})

	go runScheduled(ctx, ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUntrackedCronInterval}, "mark untracked images", u.log, func() {
		if err := u.MarkImagesAsUntracked(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images as untracked")
		}
	})

	go runScheduled(ctx, ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshVulnerabilitySummaryCronDailyView}, "refresh daily", u.log, func() {
		now := time.Now()
		lastSnapshot, err := u.querier.GetLastSnapshotDateForVulnerabilitySummary(ctx)
		if err != nil {
			u.log.WithError(err).Error("could not get last snapshot date")
		}

		startDate := lastSnapshot.Time.AddDate(0, 0, 1) // next day
		today := time.Now().Truncate(24 * time.Hour)

		days := 0
		for d := startDate; !d.After(today); d = d.AddDate(0, 0, 1) {
			if err = u.querier.RefreshVulnerabilitySummaryForDate(ctx, pgtype.Date{
				Time:  d,
				Valid: true,
			}); err != nil {
				u.log.WithError(err).Errorf("failed to refresh summary for %s", d.Format("2006-01-02"))
			}
			days++
		}
		u.log.Infof("vulnerability summary refreshed for %d days, took %f seconds\n", days, time.Since(now).Seconds())

		if err = u.querier.RefreshVulnerabilitySummaryDailyView(ctx); err != nil {
			u.log.WithError(err).Error("failed to refresh vulnerability summary daily view")
		}
	})

	go runScheduled(ctx, ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshWorkloadVulnerabilityLifetimesCronDailyView}, "refresh workload vulnerability lifetimes", u.log, func() {
		now := time.Now()
		u.log.Info("starting refresh of workload vulnerability lifetimes")

		if err := u.querier.UpsertVulnerabilityLifetimes(ctx); err != nil {
			u.log.WithError(err).Error("failed to refresh workload vulnerability lifetimes")
			return
		}

		u.log.Infof("workload vulnerability lifetimes refreshed successfully, took %f seconds", time.Since(now).Seconds())
	})
}

func (u *Updater) ResyncImageVulnerabilities(ctx context.Context) error {
	u.log.Debug("resyncing images")
	images, err := u.querier.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	for _, img := range images {
		err = u.mgr.SyncImage(ctx, img.Name, img.Tag)
		if err != nil {
			u.log.WithError(err).Errorf("failed to enqueue sync job for %s:%s", img.Name, img.Tag)
		}
	}
	return nil
}

func (u *Updater) MarkUnusedImages(ctx context.Context) error {
	rowsAffected, err := u.querier.MarkUnusedImages(ctx, sql.MarkUnusedImagesParams{
		ExcludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateFailed,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{
			Time:  time.Now().Add(-ImageMarkAge),
			Valid: true,
		},
	})
	if err != nil {
		u.log.WithError(err).Error("Failed to mark unused images")
		return err
	}

	u.log.Debugf("MarkUnusedImages affected %d rows", rowsAffected)
	return nil
}

func (u *Updater) MarkImagesAsUntracked(ctx context.Context) error {
	rowsAffected, err := u.querier.MarkImagesAsUntracked(ctx, sql.MarkImagesAsUntrackedParams{
		IncludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{
			Time:  time.Now().Add(-ImageMarkAge),
			Valid: true,
		},
	})
	if err != nil {
		u.log.WithError(err).Error("Failed to mark images as untracked")
		return err
	}
	u.log.Debugf("MarkImagesAsUntracked affected %d rows", rowsAffected)
	return nil
}

// MarkForResync Mark images for resync that have not been updated for a certain amount of time where state is not 'resync'
func (u *Updater) MarkForResync(ctx context.Context) error {
	//TODO: send in states as parameter, and not use values in sql
	err := u.querier.MarkImagesForResync(
		ctx,
		sql.MarkImagesForResyncParams{
			ThresholdTime: pgtype.Timestamptz{
				Time:  time.Now().Add(-u.resyncImagesOlderThanMinutes),
				Valid: true,
			},
			ExcludedStates: []sql.ImageState{
				sql.ImageStateResync,
				sql.ImageStateUntracked,
				sql.ImageStateFailed,
			},
		})
	if err != nil {
		return err
	}
	return nil
}
