package updater

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/manager"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
)

const (
	FetchVulnerabilityDataForImagesDefaultLimit        = 10
	MarkUntrackedCronInterval                          = "*/20 * * * *" // every 20 minutes
	MarkUnusedCronInterval                             = "*/30 * * * *" // every 30 minutes
	RefreshVulnerabilitySummaryCronDailyView           = "30 4 * * *"   // every day at 6:30 AM CEST
	RefreshWorkloadVulnerabilityLifetimesCronDailyView = "0 5 * * *"    // every day at 7:00 AM CEST (30 min later)
	ImageMarkAge                                       = 30 * time.Minute
	ResyncImagesOlderThanMinutesDefault                = 30 * 12 * time.Minute // 30 * 12 minutes = 6 hours, default for resyncing images
)

type Updater struct {
	db                           *pgxpool.Pool
	querier                      *sql.Queries
	manager                      *manager.WorkloadManager
	updateSchedule               ScheduleConfig
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	doneChan                     chan struct{}
	once                         sync.Once
	log                          *logrus.Entry
}

func NewUpdater(pool *pgxpool.Pool, source sources.Source, mgr *manager.WorkloadManager, schedule ScheduleConfig, doneChan chan struct{}, log *log.Entry) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	if doneChan == nil {
		doneChan = make(chan struct{})
	}

	return &Updater{
		db:                           pool,
		querier:                      sql.New(pool),
		source:                       source,
		manager:                      mgr,
		resyncImagesOlderThanMinutes: ResyncImagesOlderThanMinutesDefault,
		updateSchedule:               schedule,
		doneChan:                     doneChan,
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
	start := time.Now()

	images, err := u.querier.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	ctx = NewDbContext(ctx, u.querier, u.log)

	done := make(chan bool)
	batchCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	ch := make(chan *ImageVulnerabilityData, 100)

	go func() {
		defer close(done)
		if err := u.UpdateVulnerabilityData(batchCtx, ch); err != nil {
			u.log.WithError(err).Error("Failed to batch insert image vulnerability data")
			done <- false
		} else {
			done <- true
		}
	}()

	err = u.FetchVulnerabilityDataForImages(ctx, images, FetchVulnerabilityDataForImagesDefaultLimit, ch)
	close(ch)

	updateSuccess := <-done

	if err != nil {
		u.log.WithError(err).Error("Failed to fetch vulnerability data for images")
		return err
	}

	u.log.Infof("images resynced successfully: %v, in %fs", updateSuccess, time.Since(start).Seconds())

	if u.doneChan != nil {
		u.once.Do(func() {
			close(u.doneChan)
		})
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

func (u *Updater) UpdateVulnerabilityData(ctx context.Context, ch chan *ImageVulnerabilityData) error {
	start := time.Now()

	errs := make([]error, 0)
	for {
		batch, err := collections.ReadChannel(ctx, ch, 100)
		if err != nil {
			return err
		}

		if len(batch) == 0 {
			break
		}

		errs = u.upsertBatch(ctx, batch)
	}

	if len(errs) > 0 {
		u.log.Debugf("errors during batch upsert: %v", errs)
	}

	u.log.WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_errors": len(errs),
	}).Infof("vulnerability data has been updated")

	return nil
}

func (u *Updater) upsertBatch(ctx context.Context, batch []*ImageVulnerabilityData) []error {
	if len(batch) == 0 {
		return nil
	}
	var errs []error
	var batchErr error

	imageStates := make([]sql.BatchUpdateImageStateParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	images := make([]manager.Image, 0, len(batch))

	for _, i := range batch {
		images = append(images, manager.Image{
			Name: i.ImageName,
			Tag:  i.ImageTag,
		})
		cves = append(cves, i.ToCveSqlParams()...)
		vulns = append(vulns, u.ToVulnerabilitySqlParams(ctx, i)...)
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})
	}

	start := time.Now()
	errors := 0
	u.querier.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert cves")
			batchErr = err
			errors++
			errs = append(errs, err)
		}
	})
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   len(cves) - errors,
		"num_errors": errors,
	}).Infof("upserted batch of CVEs")

	start = time.Now()
	errors = 0
	u.querier.BatchUpsertVulnerabilities(ctx, vulns).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert vulnerabilities")
			batchErr = err
			errors++
			errs = append(errs, err)
		}
	})
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   len(vulns) - errors,
		"num_errors": errors,
	}).Infof("upserted batch of vulnerabilities")

	if len(batch) > 0 {
		if err := u.manager.AddJob(ctx, &manager.UpsertVulnerabilitySummariesJob{
			Images: images,
		}); err != nil {
			u.log.WithError(err).Error("failed to enqueue vulnerability summaries job")
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		start = time.Now()
		errors = 0
		u.querier.BatchUpdateImageState(ctx, imageStates).Exec(func(i int, err error) {
			if err != nil {
				u.log.WithError(err).Debug("failed to batch update image state")
				batchErr = err
				errors++
				errs = append(errs, err)
			}
		})
		u.log.WithError(batchErr).WithFields(logrus.Fields{
			"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
			"num_rows":   len(imageStates),
			"num_errors": errors,
		}).Infof("updated image states to 'updated'")
	}

	return errs
}
