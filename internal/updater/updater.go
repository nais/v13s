package updater

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
)

const (
	FetchVulnerabilityDataForImagesDefaultLimit = 10
	DefaultMarkUntrackedInterval                = 20 * time.Minute
	DefaultResyncImagesOlderThanMinutes         = 60 * 12 * time.Minute // 12 hours
	DefaultMarkAsUntrackedAge                   = 30 * time.Minute
)

type Updater struct {
	db                           *pgxpool.Pool
	querier                      *sql.Queries
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	updateInterval               time.Duration
	log                          *logrus.Entry
}

func NewUpdater(pool *pgxpool.Pool, source sources.Source, updateInterval time.Duration, log *log.Entry) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	return &Updater{
		db:                           pool,
		querier:                      sql.New(pool),
		source:                       source,
		resyncImagesOlderThanMinutes: DefaultResyncImagesOlderThanMinutes,
		updateInterval:               updateInterval,
		log:                          log,
	}
}

// Run TODO: create a state/log table and log errors? maybe successfull and failed runs?
func (u *Updater) Run(ctx context.Context) {
	go runAtInterval(ctx, u.updateInterval, "mark and resync images", u.log, func() {
		if err := u.MarkUnusedImages(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images as unused")
			return
		}
		if err := u.MarkForResync(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images for resync")
			return
		}
		u.log.Info("resyncing images")
		if err := u.ResyncImages(ctx); err != nil {
			u.log.WithError(err).Error("Failed to resync images")
		}
	})

	go runAtInterval(ctx, DefaultMarkUntrackedInterval, "mark untracked images", u.log, func() {
		if err := u.MarkImagesAsUntracked(ctx); err != nil {
			u.log.WithError(err).Error("Failed to mark images as untracked")
		}
	})

	go runAtInterval(ctx, 12*time.Hour, "refresh vulnerability summary for dates", u.log, func() {
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
}

// ResyncImages Resync images that have state 'initialized' or 'resync'
func (u *Updater) ResyncImages(ctx context.Context) error {
	start := time.Now()

	images, err := u.querier.GetImagesScheduledForSync(ctx)
	if err != nil {
		return err
	}

	ctx = NewDbContext(ctx, u.querier, u.log)

	done := make(chan bool)
	defer close(done)

	batchCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	ch := make(chan *ImageVulnerabilityData, 100)

	go func() {

		if err = u.UpdateVulnerabilityData(batchCtx, ch); err != nil {
			u.log.WithError(err).Error("Failed to batch insert image vulnerability data")
			//errchan <- err
			done <- false
		} else {
			done <- true
		}
	}()

	err = u.FetchVulnerabilityDataForImages(ctx, images, FetchVulnerabilityDataForImagesDefaultLimit, ch)
	if err != nil {
		u.log.WithError(err).Error("Failed to fetch vulnerability data for images")
		return err
	}

	close(ch)
	updateSuccess := <-done

	u.log.Infof("images resynced successfully: %v, in %fs", updateSuccess, time.Since(start).Seconds())
	return nil
}

func (u *Updater) MarkUnusedImages(ctx context.Context) error {
	err := u.querier.MarkUnusedImages(ctx, sql.MarkUnusedImagesParams{
		ExcludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateFailed,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{
			Time: time.Now().Add(-DefaultMarkAsUntrackedAge),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (u *Updater) MarkImagesAsUntracked(ctx context.Context) error {
	return u.querier.MarkImagesAsUntracked(ctx, sql.MarkImagesAsUntrackedParams{
		IncludedStates: []sql.ImageState{
			sql.ImageStateResync,
			sql.ImageStateInitialized,
		},
		ThresholdTime: pgtype.Timestamptz{
			Time: time.Now().Add(-DefaultMarkAsUntrackedAge),
		},
	})
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

	errors := 0
	errs := make([]error, 0)

	imageStates := make([]sql.BatchUpdateImageStateParams, 0)
	cves := make([]sql.BatchUpsertCveParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)

	for _, i := range batch {
		cves = append(cves, i.ToCveSqlParams()...)
		vulns = append(vulns, i.ToVulnerabilitySqlParams()...)
		summaries = append(summaries, i.ToVulnerabilitySummarySqlParams())
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})
	}

	start := time.Now()
	var batchErr error
	u.querier.BatchUpsertCve(ctx, cves).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert cves")
			batchErr = err
			errors++
			errs = append(errs, err)
		}
	})
	upserted := len(cves) - errors
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch of cves")

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
	upserted = len(vulns) - errors
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch of vulnerabilities")

	start = time.Now()
	errors = 0
	u.querier.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			u.log.WithError(err).Debug("failed to batch upsert vulnerability summary")
			batchErr = err
			errors++
			errs = append(errs, err)
		}
	})
	upserted = len(summaries) - errors
	u.log.WithError(batchErr).WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   upserted,
		"num_errors": errors,
	}).Infof("upserted batch of summaries")

	if len(errs) == 0 {
		start = time.Now()
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
			"num_rows":   upserted,
			"num_errors": errors,
		}).Infof("upserted batch of image states (updated)")
	}
	return errs
}

func runAtInterval(ctx context.Context, interval time.Duration, name string, log *logrus.Entry, job func()) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("job stopped")
			return
		case <-ticker.C:
			// TODO: set as debug
			log.Infof("running scheduled job '%s' at interval %v", name, interval)
			job()
		}
	}
}
