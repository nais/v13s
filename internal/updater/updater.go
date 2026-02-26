package updater

import (
	"context"
	"fmt"
	"sort"
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
	// ResyncImagesOlderThanMinutesDefault is the default duration after which images are marked for resync
	ResyncImagesOlderThanMinutesDefault = 60 * 4 * time.Minute
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
		if err := u.Update(batchCtx, ch); err != nil {
			u.log.WithError(err).Error("Failed to batch insert image vulnerability data")
			done <- false
		} else {
			done <- true
		}
	}()

	// TODO: riverjob worker to fetch vulnerability data for images
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
	// TODO: send in states as parameter, and not use values in sql
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

func (u *Updater) Update(ctx context.Context, ch chan *ImageVulnerabilityData) error {
	start := time.Now()

	for {
		batch, err := collections.ReadChannel(ctx, ch, 100)
		if err != nil {
			return err
		}

		if len(batch) == 0 {
			break
		}

		u.BatchUpdateVulnerabilityData(ctx, batch)
	}

	u.log.WithFields(logrus.Fields{
		"duration": fmt.Sprintf("%fs", time.Since(start).Seconds()),
	}).Infof("vulnerability data has been updated")

	return nil
}

func (u *Updater) ensureCanonicalsPresent(cves []sql.BatchUpsertCveParams, cveAliases []sql.BatchUpsertCveAliasParams) []sql.BatchUpsertCveParams {
	cveIDSet := make(map[string]struct{})
	for _, cve := range cves {
		cveIDSet[cve.CveID] = struct{}{}
	}
	missingCanonicals := make(map[string]struct{})
	missingAliases := make(map[string]struct{})
	for _, alias := range cveAliases {
		if _, ok := cveIDSet[alias.CanonicalCveID]; !ok {
			missingCanonicals[alias.CanonicalCveID] = struct{}{}
		}
		if _, ok := cveIDSet[alias.Alias]; !ok {
			missingAliases[alias.Alias] = struct{}{}
		}
	}
	for canonical := range missingCanonicals {
		u.log.WithField("canonical", canonical).Warning("Canonical CVE referenced by alias is missing from batch; adding minimal record")
		cves = append(cves, sql.BatchUpsertCveParams{
			CveID: canonical,
			Refs:  map[string]string{},
		})
	}
	for alias := range missingAliases {
		u.log.WithField("alias", alias).Debug("Alias CVE referenced by alias mapping is missing from batch; adding minimal record")
		cves = append(cves, sql.BatchUpsertCveParams{
			CveID: alias,
			Refs:  map[string]string{},
		})
	}
	return cves
}

func (u *Updater) BatchUpdateVulnerabilityData(ctx context.Context, images []*ImageVulnerabilityData) {
	cves := make([]sql.BatchUpsertCveParams, 0)
	cveAliases := make([]sql.BatchUpsertCveAliasParams, 0)
	vulns := make([]sql.BatchUpsertVulnerabilitiesParams, 0)
	imageStates := make([]sql.BatchUpdateImageStateParams, 0)

	for _, i := range images {
		cves = append(cves, i.ToCveSqlParams()...)
		vulns = append(vulns, u.ToVulnerabilitySqlParams(ctx, i)...)
		cveAliases = append(cveAliases, i.ToCveAliasSqlParams()...)
		imageStates = append(imageStates, sql.BatchUpdateImageStateParams{
			State: sql.ImageStateUpdated,
			Name:  i.ImageName,
			Tag:   i.ImageTag,
		})
	}

	cves = u.ensureCanonicalsPresent(cves, cveAliases)

	sortByFields(cves, func(x sql.BatchUpsertCveParams) string {
		return x.CveID
	})
	sortByFields(vulns,
		func(x sql.BatchUpsertVulnerabilitiesParams) string {
			return x.ImageName
		},
		func(x sql.BatchUpsertVulnerabilitiesParams) string {
			return x.ImageTag
		},
	)
	sortByFields(imageStates,
		func(x sql.BatchUpdateImageStateParams) string { return x.Name },
		func(x sql.BatchUpdateImageStateParams) string { return x.Tag },
	)

	u.runExec("upsert CVEs", len(cves), u.querier.BatchUpsertCve(ctx, cves).Exec)
	u.runExec("upsert CVE aliases", len(cveAliases), u.querier.BatchUpsertCveAlias(ctx, cveAliases).Exec)
	u.runExec("upsert vulnerabilities", len(vulns), u.querier.BatchUpsertVulnerabilities(ctx, vulns).Exec)

	for _, i := range images {
		if err := u.querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
			ImageName: i.ImageName,
			ImageTag:  i.ImageTag,
		}); err != nil {
			u.log.WithError(err).Error("recalculate vulnerability summary")
		}
	}

	u.runExec("update image states", len(images), u.querier.BatchUpdateImageState(ctx, imageStates).Exec)
}

func (u *Updater) runExec(
	label string,
	totalRows int,
	exec func(handler func(int, error)),
) (errCount int) {
	start := time.Now()
	handler := func(i int, err error) {
		if err == nil {
			return
		}
		errCount++
		u.log.WithError(err).WithFields(logrus.Fields{
			"batch": label,
			"row":   i,
		}).Error("batch row failed")
	}

	exec(handler)

	entry := u.log.WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   totalRows - errCount,
		"num_errors": errCount,
	})
	if errCount > 0 {
		entry.Error(label)
	} else {
		entry.Info(label)
	}

	return errCount
}

func sortByFields[T any](items []T, getters ...func(T) string) {
	sort.SliceStable(items, func(i, j int) bool {
		for _, get := range getters {
			a, b := get(items[i]), get(items[j])
			if a < b {
				return true
			}
			if a > b {
				return false
			}
		}
		return false
	})
}
