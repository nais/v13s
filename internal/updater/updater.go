package updater

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/log"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nais/v13s/internal/collections"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/sirupsen/logrus"
)

const (
	FetchVulnerabilityDataForImagesDefaultLimit        = 10
	MarkUntrackedCronInterval                          = "*/20 * * * *" // every 20 minutes
	MarkUnusedCronInterval                             = "*/30 * * * *" // every 30 minutes
	RefreshVulnerabilitySummaryCronDailyView           = "30 4 * * *"   // every day at 6:30 AM CEST
	RefreshWorkloadVulnerabilityLifetimesCronDailyView = "0 5 * * *"    // every day at 7:00 AM CEST (30 min later)
	SyncKevCronInterval                                = "0 6 * * *"    // every day at 8:00 AM CEST
	SyncOsvCronInterval                                = "0 7 * * *"    // every day at 9:00 AM CEST
	RekeySuppressedAliasesCronInterval                 = "0 8 * * *"    // every day at 10:00 AM CEST
	ResyncCycleLockKey                                 = int64(7705370001)
	ImageMarkAge                                       = 30 * time.Minute
	// ResyncImagesOlderThanMinutesDefault is the default duration after which images are marked for resync
	ResyncImagesOlderThanMinutesDefault = 6 * time.Hour
)

type Updater struct {
	pool                         *pgxpool.Pool
	querier                      *sql.Queries
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	log                          *logrus.Entry
	kevFetcher                   *kev.Fetcher
	osvFetcher                   *osv.Fetcher
	runtimeConfig                RuntimeConfig
	lifecycle                    updaterLifecycle
	cycle                        updaterCycle
}

type updaterLifecycle struct {
	mu      sync.Mutex
	jobs    []Job
	started atomic.Bool
}

type updaterCycle struct {
	running atomic.Bool
	step    func(context.Context) error
}

func NewUpdater(pool *pgxpool.Pool, source sources.Source, schedule ScheduleConfig, log *log.Entry, kevCfg config.KevConfig, osvCfg config.OsvConfig) *Updater {
	return NewUpdaterWithRuntimeConfig(pool, source, log, kevCfg, osvCfg, DefaultRuntimeConfig(schedule))
}

func NewUpdaterWithRuntimeConfig(pool *pgxpool.Pool, source sources.Source, log *log.Entry, kevCfg config.KevConfig, osvCfg config.OsvConfig, runtimeCfg RuntimeConfig) *Updater {
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}

	querier := sql.New(pool)
	u := &Updater{
		pool:                         pool,
		querier:                      querier,
		source:                       source,
		resyncImagesOlderThanMinutes: ResyncImagesOlderThanMinutesDefault,
		log:                          log,
		kevFetcher:                   kev.NewFetcherWithClient(kev.NewClientWithURL(kevCfg.CatalogURL), querier, log),
		osvFetcher:                   osv.NewFetcherWithClient(osv.NewClientWithURL(osvCfg.BaseURL), pool, log),
		runtimeConfig:                runtimeCfg,
	}
	u.cycle.step = u.runResyncCycle
	return u
}

// Run starts updater jobs and is kept for backward compatibility.
func (u *Updater) Run(ctx context.Context) {
	u.Start(ctx)
}

func (u *Updater) Start(ctx context.Context) {
	if !u.lifecycle.started.CompareAndSwap(false, true) {
		u.log.Warn("updater already started")
		return
	}

	var jobs []Job
	if !u.runtimeConfig.OrchestrationEnabled {
		jobs = u.buildLegacyJobs()
		u.log.WithFields(logrus.Fields{
			"mode": "legacy",
			"jobs": len(jobs),
		}).Info("starting updater jobs with legacy scheduling; per-job Enabled/cron overrides are ignored in this mode")
	} else {
		jobs = u.buildRuntimeJobs()
		u.log.WithFields(logrus.Fields{
			"mode": "runtime",
			"jobs": len(jobs),
		}).Info("starting updater jobs with runtime orchestration")
	}

	u.lifecycle.mu.Lock()
	defer u.lifecycle.mu.Unlock()

	if !u.lifecycle.started.Load() {
		return
	}
	u.lifecycle.jobs = jobs
	for _, job := range jobs {
		job.Start(ctx)
	}
}

func (u *Updater) Stop(ctx context.Context) error {
	u.lifecycle.mu.Lock()
	jobs := u.lifecycle.jobs
	u.lifecycle.jobs = nil
	u.lifecycle.mu.Unlock()

	var stopErrs []error
	for _, job := range jobs {
		if err := job.Stop(ctx); err != nil {
			u.log.WithError(err).WithField("job", job.Name()).Error("failed to stop updater job")
			stopErrs = append(stopErrs, fmt.Errorf("stopping job %q: %w", job.Name(), err))
		}
	}

	u.lifecycle.started.Store(false)
	return errors.Join(stopErrs...)
}

func (u *Updater) runMarkUnusedImages(ctx context.Context) error {
	return u.MarkUnusedImages(ctx)
}

func (u *Updater) runMarkImagesAsUntracked(ctx context.Context) error {
	return u.MarkImagesAsUntracked(ctx)
}

func (u *Updater) runRefreshDailySummary(ctx context.Context) error {
	now := time.Now()
	lastSnapshot, err := u.querier.GetLastSnapshotDateForVulnerabilitySummary(ctx)
	if err != nil {
		return fmt.Errorf("getting last snapshot date: %w", err)
	}

	startDate := lastSnapshot.Time.AddDate(0, 0, 1) // next day
	today := time.Now().Truncate(24 * time.Hour)

	var refreshErrs []error
	days := 0
	for d := startDate; !d.After(today); d = d.AddDate(0, 0, 1) {
		if err = u.querier.RefreshVulnerabilitySummaryForDate(ctx, pgtype.Date{
			Time:  d,
			Valid: true,
		}); err != nil {
			u.log.Errorf("refreshing summary for %s: %v (continuing)", d.Format("2006-01-02"), err)
			refreshErrs = append(refreshErrs, fmt.Errorf("refreshing summary for %s: %w", d.Format("2006-01-02"), err))
			continue
		}
		days++
	}
	u.log.Infof("vulnerability summary refreshed for %d days, took %f seconds", days, time.Since(now).Seconds())

	if err = u.querier.RefreshVulnerabilitySummaryDailyView(ctx); err != nil {
		return fmt.Errorf("refreshing vulnerability summary daily view: %w", err)
	}
	return errors.Join(refreshErrs...)
}

func (u *Updater) runRefreshWorkloadVulnerabilityLifetimes(ctx context.Context) error {
	now := time.Now()
	u.log.Info("starting refresh of workload vulnerability lifetimes")

	if err := u.querier.UpsertVulnerabilityLifetimes(ctx); err != nil {
		return fmt.Errorf("refreshing workload vulnerability lifetimes: %w", err)
	}

	u.log.Infof("workload vulnerability lifetimes refreshed successfully, took %f seconds", time.Since(now).Seconds())
	return nil
}

func (u *Updater) runSyncKevCatalog(ctx context.Context) error {
	return u.kevFetcher.Sync(ctx)
}

func (u *Updater) runSyncOsvFixVersions(ctx context.Context) error {
	return u.osvFetcher.Sync(ctx)
}

func (u *Updater) runRekeySuppressedAliases(ctx context.Context) error {
	rowsAffected, err := u.querier.RekeySuppressedAliasesToCanonical(ctx)
	if err != nil {
		return err
	}
	if rowsAffected > 0 {
		u.log.WithField("rows", rowsAffected).Info("rekeyed suppressed aliases to canonical")
	}
	return nil
}

func (u *Updater) buildLegacyJobs() []Job {
	return []Job{
		newScheduledJob("mark and resync images and sync workload vulnerabilities", u.runtimeConfig.Resync.Schedule, u.log, u.RunCycle),
		newScheduledJob("mark unused images", ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUnusedCronInterval}, u.log, u.runMarkUnusedImages),
		newScheduledJob("mark untracked images", ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUntrackedCronInterval}, u.log, u.runMarkImagesAsUntracked),
		newScheduledJob("refresh daily", ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshVulnerabilitySummaryCronDailyView}, u.log, u.runRefreshDailySummary),
		newScheduledJob("refresh workload vulnerability lifetimes", ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshWorkloadVulnerabilityLifetimesCronDailyView}, u.log, u.runRefreshWorkloadVulnerabilityLifetimes),
		newScheduledJob("sync CISA KEV catalog", ScheduleConfig{Type: SchedulerCron, CronExpr: SyncKevCronInterval}, u.log, u.runSyncKevCatalog),
		newScheduledJob("sync OSV fix versions", ScheduleConfig{Type: SchedulerCron, CronExpr: SyncOsvCronInterval}, u.log, u.runSyncOsvFixVersions),
		newScheduledJob("rekey suppressed aliases to canonical", ScheduleConfig{Type: SchedulerCron, CronExpr: RekeySuppressedAliasesCronInterval}, u.log, u.runRekeySuppressedAliases),
	}
}

func (u *Updater) buildRuntimeJobs() []Job {
	jobs := make([]Job, 0, 8)

	add := func(cfg JobRuntimeConfig, name string, run func(context.Context) error) {
		if !cfg.Enabled {
			u.log.WithField("job", name).Info("updater job disabled by config")
			return
		}
		jobs = append(jobs, newScheduledJob(name, cfg.Schedule, u.log, run))
	}

	add(u.runtimeConfig.Resync, "mark and resync images and sync workload vulnerabilities", u.RunCycle)
	add(u.runtimeConfig.MarkUnused, "mark unused images", u.runMarkUnusedImages)
	add(u.runtimeConfig.MarkUntracked, "mark untracked images", u.runMarkImagesAsUntracked)
	add(u.runtimeConfig.RefreshDailySummary, "refresh daily", u.runRefreshDailySummary)
	add(u.runtimeConfig.RefreshWorkloadLifetimes, "refresh workload vulnerability lifetimes", u.runRefreshWorkloadVulnerabilityLifetimes)
	add(u.runtimeConfig.SyncKev, "sync CISA KEV catalog", u.runSyncKevCatalog)
	add(u.runtimeConfig.SyncOsv, "sync OSV fix versions", u.runSyncOsvFixVersions)
	add(u.runtimeConfig.RekeySuppressedAliases, "rekey suppressed aliases to canonical", u.runRekeySuppressedAliases)

	return jobs
}

func (u *Updater) RunCycle(ctx context.Context) error {
	if !u.cycle.running.CompareAndSwap(false, true) {
		u.log.Info("resync cycle already running, skipping trigger")
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeSkipped)
		return nil
	}
	defer u.cycle.running.Store(false)

	step := u.cycle.step
	if step == nil {
		step = u.runResyncCycle
	}

	return step(ctx)
}

func (u *Updater) runResyncCycle(ctx context.Context) error {
	return u.withResyncAdvisoryLock(ctx, func(ctx context.Context) error {
		var errs []error
		if err := u.RecoverUntrackedImages(ctx); err != nil {
			errs = append(errs, fmt.Errorf("recovering untracked images: %w", err))
		}
		if err := u.MarkForResync(ctx); err != nil {
			errs = append(errs, fmt.Errorf("marking images for resync: %w", err))
		}
		if err := u.ResyncImageVulnerabilities(ctx); err != nil {
			errs = append(errs, fmt.Errorf("resyncing image vulnerabilities: %w", err))
		}
		return errors.Join(errs...)
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

func (u *Updater) withResyncAdvisoryLock(ctx context.Context, run func(context.Context) error) error {
	if u.pool == nil {
		if err := run(ctx); err != nil {
			metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeFailed)
			return err
		}
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeSuccess)
		return nil
	}

	conn, err := u.pool.Acquire(ctx)
	if err != nil {
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeFailed)
		return fmt.Errorf("acquiring DB connection for resync cycle: %w", err)
	}
	lockQuerier := sql.New(conn)

	locked, err := lockQuerier.TryAdvisoryLock(ctx, ResyncCycleLockKey)
	if err != nil {
		conn.Release()
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeFailed)
		return fmt.Errorf("acquiring resync cycle advisory lock: %w", err)
	}
	if !locked {
		conn.Release()
		u.log.Info("resync cycle already running on another pod, skipping trigger")
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeSkipped)
		return nil
	}

	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		released, unlockErr := lockQuerier.AdvisoryUnlock(unlockCtx, ResyncCycleLockKey)
		if unlockErr != nil {
			u.log.WithError(unlockErr).Warn("failed to release resync cycle advisory lock, discarding connection")
			if closeErr := conn.Hijack().Close(context.Background()); closeErr != nil {
				u.log.WithError(closeErr).Warn("failed to close connection after advisory unlock failure")
			}
			return
		}
		if !released {
			u.log.Warn("resync cycle advisory lock was not held at unlock time")
		}
		conn.Release()
	}()

	if err := run(ctx); err != nil {
		metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeFailed)
		return err
	}

	metrics.RecordUpdaterResyncCycle(metrics.UpdaterResyncCycleOutcomeSuccess)
	return nil
}

func (u *Updater) RecoverUntrackedImages(ctx context.Context) error {
	rowsAffected, err := u.querier.MarkUntrackedImagesForResync(ctx)
	if err != nil {
		u.log.WithError(err).Error("Failed to mark untracked images for resync")
		return err
	}
	if rowsAffected > 0 {
		u.log.Infof("MarkUntrackedImagesForResync recovered %d untracked images", rowsAffected)
	}
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

		if err := u.BatchUpdateVulnerabilityData(ctx, batch); err != nil {
			return err
		}
	}

	u.log.WithFields(logrus.Fields{
		"duration": fmt.Sprintf("%fs", time.Since(start).Seconds()),
	}).Infof("vulnerability data has been updated")

	return nil
}

func (u *Updater) BatchUpdateVulnerabilityData(ctx context.Context, images []*ImageVulnerabilityData) error {
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

	workloadStates := make([]sql.BatchUpdateWorkloadStateByImageParams, 0, len(images))
	for _, i := range images {
		workloadStates = append(workloadStates, sql.BatchUpdateWorkloadStateByImageParams{
			State:     sql.WorkloadStateUpdated,
			ImageName: i.ImageName,
			ImageTag:  i.ImageTag,
		})
	}
	sortByFields(workloadStates,
		func(x sql.BatchUpdateWorkloadStateByImageParams) string { return x.ImageName },
		func(x sql.BatchUpdateWorkloadStateByImageParams) string { return x.ImageTag },
	)
	if errCount := u.runExec("update workload states", len(workloadStates), u.querier.BatchUpdateWorkloadStateByImage(ctx, workloadStates).Exec); errCount > 0 {
		u.log.Errorf("skipping image state update: %d workload state update(s) failed", errCount)
		return fmt.Errorf("batch workload state update had %d failure(s), image state update skipped", errCount)
	}

	u.runExec("update image states", len(images), u.querier.BatchUpdateImageState(ctx, imageStates).Exec)
	return nil
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
