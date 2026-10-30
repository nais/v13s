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
	v13sdatabase "github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/nais/v13s/internal/sources/osv"
	"github.com/sirupsen/logrus"
)

const (
	FetchVulnerabilityDataForImagesDefaultLimit = 10
	ResyncCycleLockKey                          = int64(7705370001)
	ImageMarkAge                                = 30 * time.Minute
	// ResyncImagesOlderThanMinutesDefault is the default duration after which images are marked for resync
	ResyncImagesOlderThanMinutesDefault = 6 * time.Hour
	ResyncBatchTimeoutDefault           = 15 * time.Minute
	BatchWriteTimeoutDefault            = 15 * time.Minute
)

type Updater struct {
	pool                         *pgxpool.Pool
	querier                      *sql.Queries
	source                       sources.Source
	resyncImagesOlderThanMinutes time.Duration
	resyncBatchTimeout           time.Duration
	batchWriteTimeout            time.Duration
	log                          *logrus.Entry
	kevFetcher                   *kev.Fetcher
	osvFetcher                   *osv.Fetcher
	cveWorkloadCountsRefresher   *v13sdatabase.CveWorkloadCountsRefresher
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
	return NewUpdaterWithRuntimeConfig(pool, source, log, kevCfg, osvCfg, RuntimeConfig{Resync: JobRuntimeConfig{Enabled: true, Schedule: schedule}})
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
		resyncBatchTimeout:           ResyncBatchTimeoutDefault,
		batchWriteTimeout:            BatchWriteTimeoutDefault,
		log:                          log,
		kevFetcher:                   kev.NewFetcher(pool, log, kev.SourcesFromConfig(kevCfg)...),
		osvFetcher:                   osv.NewFetcherWithClient(osv.NewClientWithURL(osvCfg.BaseURL), pool, log),
		cveWorkloadCountsRefresher:   v13sdatabase.NewCveWorkloadCountsRefresher(pool, log),
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

	jobs := u.buildJobs()
	u.log.WithField("jobs", len(jobs)).Info("starting updater jobs")

	u.lifecycle.mu.Lock()
	defer u.lifecycle.mu.Unlock()

	if !u.lifecycle.started.Load() {
		return
	}
	u.lifecycle.jobs = jobs
	// job.Start is called while holding the lock to prevent Stop from racing in
	// and clearing the job list before these goroutines are scheduled.
	// Job.Start implementations must be fast (goroutine spawn + cron parse only)
	// and must not call back into Updater to avoid deadlock.
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

func (u *Updater) buildJobs() []Job {
	jobs := make([]Job, 0, 9)

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
	add(u.runtimeConfig.SyncKev, "sync KEV catalogs", u.runSyncKevCatalog)
	add(u.runtimeConfig.SyncOsv, "sync OSV fix versions", u.runSyncOsvFixVersions)
	add(u.runtimeConfig.RekeySuppressedAliases, "rekey suppressed aliases to canonical", u.runRekeySuppressedAliases)
	add(u.runtimeConfig.RefreshCveWorkloadCounts, "refresh CVE workload counts", u.cveWorkloadCountsRefresher.Refresh)

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
	batchCtx, cancel := context.WithTimeout(ctx, u.resyncBatchTimeout)
	defer cancel()

	ch := make(chan *ImageVulnerabilityData, 100)

	go func() {
		defer close(done)
		if err := u.Update(ctx, ch); err != nil {
			u.log.WithError(err).Error("Failed to batch insert image vulnerability data")
			done <- false
		} else {
			done <- true
		}
	}()

	// TODO: riverjob worker to fetch vulnerability data for images
	err = u.FetchVulnerabilityDataForImages(batchCtx, images, FetchVulnerabilityDataForImagesDefaultLimit, ch)
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

	var batchErrs []error
	for {
		batch, err := collections.ReadChannel(ctx, ch, 100)
		if err != nil {
			return errors.Join(append(batchErrs, err)...)
		}

		if len(batch) == 0 {
			break
		}

		writeCtx, cancel := context.WithTimeout(ctx, u.batchWriteTimeout)
		err = u.BatchUpdateVulnerabilityData(writeCtx, batch)
		err = errors.Join(err, writeCtx.Err())
		cancel()
		if err != nil {
			u.log.WithError(err).WithField("images", len(batch)).Error("one or more images in batch failed, continuing with next batch")
			batchErrs = append(batchErrs, err)
		}
	}

	u.log.WithFields(logrus.Fields{
		"duration":       fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"failed_batches": len(batchErrs),
	}).Info("finished updating vulnerability data")

	return errors.Join(batchErrs...)
}

func (u *Updater) BatchUpdateVulnerabilityData(ctx context.Context, images []*ImageVulnerabilityData) error {
	since, err := u.DetermineSeveritySince(ctx, images)
	if err != nil {
		u.log.Errorf("determine severitySince: %v", err)
	}

	var imageErrs []error
	recordError := func(image *ImageVulnerabilityData, err error) {
		u.log.WithError(err).WithFields(logrus.Fields{
			"image":             image.ImageName,
			"tag":               image.ImageTag,
			"source":            image.Source,
			"received_findings": len(image.Vulnerabilities),
		}).Error("failed to update vulnerability data for image")
		imageErrs = append(imageErrs, fmt.Errorf("updating image %s:%s: %w", image.ImageName, image.ImageTag, err))
	}

	writtenImages := make([]*ImageVulnerabilityData, 0, len(images))
	for _, image := range images {
		if err := u.writeImageVulnerabilityData(ctx, image, since); err != nil {
			recordError(image, err)
			continue
		}
		writtenImages = append(writtenImages, image)
	}

	for _, image := range writtenImages {
		if err := u.finalizeImageVulnerabilityData(ctx, image); err != nil {
			recordError(image, err)
			continue
		}
		u.log.WithFields(logrus.Fields{
			"image":             image.ImageName,
			"tag":               image.ImageTag,
			"source":            image.Source,
			"received_findings": len(image.Vulnerabilities),
		}).Info("vulnerability data written for image")
	}
	return errors.Join(imageErrs...)
}

func (u *Updater) writeImageVulnerabilityData(ctx context.Context, image *ImageVulnerabilityData, since map[SeveritySinceKey]time.Time) error {
	cves := image.ToCveSqlParams()
	vulns := image.ToVulnerabilitySqlParams(since)
	cveAliases := image.ToCveAliasSqlParams()

	sortByFields(cves, func(x sql.BatchUpsertCveParams) string {
		return x.CveID
	})
	if err := u.runExec("upsert CVEs", len(cves), u.querier.BatchUpsertCve(ctx, cves).Exec); err != nil {
		return err
	}
	if err := u.runExec("upsert CVE aliases", len(cveAliases), u.querier.BatchUpsertCveAlias(ctx, cveAliases).Exec); err != nil {
		return err
	}
	if err := u.runExec("upsert vulnerabilities", len(vulns), u.querier.BatchUpsertVulnerabilities(ctx, vulns).Exec); err != nil {
		return err
	}

	if len(cves) > 0 {
		cveIDs := make([]string, 0, len(cves))
		seen := make(map[string]struct{}, len(cves))
		for _, c := range cves {
			if _, ok := seen[c.CveID]; ok {
				continue
			}
			seen[c.CveID] = struct{}{}
			cveIDs = append(cveIDs, c.CveID)
		}

		updated, err := u.querier.UpdateCvePriorityForCves(ctx, cveIDs)
		if err != nil {
			return fmt.Errorf("updating cve priority after upserting CVEs: %w", err)
		}
		if updated > 0 {
			u.log.WithField("rows", updated).Debug("updated cve priorities")
		}
	}
	return nil
}

func (u *Updater) finalizeImageVulnerabilityData(ctx context.Context, image *ImageVulnerabilityData) error {
	if err := u.querier.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
		ImageName: image.ImageName,
		ImageTag:  image.ImageTag,
	}); err != nil {
		return fmt.Errorf("recalculating vulnerability summary: %w", err)
	}

	workloadStates := []sql.BatchUpdateWorkloadStateByImageParams{{
		State:     sql.WorkloadStateUpdated,
		ImageName: image.ImageName,
		ImageTag:  image.ImageTag,
	}}
	if err := u.runExec("update workload states", len(workloadStates), u.querier.BatchUpdateWorkloadStateByImage(ctx, workloadStates).Exec); err != nil {
		return err
	}

	imageStates := []sql.BatchUpdateImageStateParams{{
		State: sql.ImageStateUpdated,
		Name:  image.ImageName,
		Tag:   image.ImageTag,
	}}
	return u.runExec("update image states", len(imageStates), u.querier.BatchUpdateImageState(ctx, imageStates).Exec)
}

func (u *Updater) runExec(
	label string,
	totalRows int,
	exec func(handler func(int, error)),
) error {
	start := time.Now()
	var rowErrs []error
	handler := func(i int, err error) {
		if err == nil {
			return
		}
		rowErrs = append(rowErrs, fmt.Errorf("%s row %d: %w", label, i, err))
		u.log.WithError(err).WithFields(logrus.Fields{
			"batch": label,
			"row":   i,
		}).Error("batch row failed")
	}

	exec(handler)

	entry := u.log.WithFields(logrus.Fields{
		"duration":   fmt.Sprintf("%fs", time.Since(start).Seconds()),
		"num_rows":   totalRows - len(rowErrs),
		"num_errors": len(rowErrs),
	})
	if len(rowErrs) > 0 {
		entry.Error(label)
	} else {
		entry.Debug(label)
	}

	return errors.Join(rowErrs...)
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
