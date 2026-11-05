package updater

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingSummaryDB struct {
	sql.DBTX
	err             error
	failAt          int
	summaryWrites   int
	nonEmptyBatches int
}

func (db *failingSummaryDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	db.summaryWrites++
	if db.summaryWrites == db.failAt {
		return pgconn.CommandTag{}, db.err
	}
	return pgconn.CommandTag{}, nil
}

func (db *failingSummaryDB) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	if batch.Len() > 0 {
		db.nonEmptyBatches++
	}
	return &contextBatchResults{ctx: ctx}
}

func TestBatchUpdateVulnerabilityData_SummaryWriteFailure(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("summary_%d", failAt), func(t *testing.T) {
			log, _ := logrustest.NewNullLogger()
			writeErr := errors.New("summary storage unavailable")
			db := &failingSummaryDB{err: writeErr, failAt: failAt}
			u := &Updater{
				querier: sql.New(db),
				log:     log.WithField("test", t.Name()),
			}

			err := u.BatchUpdateVulnerabilityData(t.Context(), []*ImageVulnerabilityData{
				{ImageName: "same-image", ImageTag: "dev"},
				{ImageName: "same-image", ImageTag: "prod"},
			})

			require.ErrorIs(t, err, writeErr)
			require.Zero(t, db.nonEmptyBatches, "workloads and images must not be marked updated")
		})
	}
}

type snapshotDateRow struct {
	date pgtype.Date
}

func (row snapshotDateRow) Scan(dest ...any) error {
	*dest[0].(*pgtype.Date) = row.date
	return nil
}

type dailySummaryDB struct {
	sql.DBTX
	latest   pgtype.Date
	failDate string
	attempts map[string]int
	err      error
}

func (db *dailySummaryDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return snapshotDateRow{date: db.latest}
}

func (db *dailySummaryDB) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	if len(args) == 0 {
		return pgconn.CommandTag{}, nil
	}
	date := args[0].(pgtype.Date)
	key := date.Time.Format(time.DateOnly)
	db.attempts[key]++
	if key == db.failDate && db.attempts[key] == 1 {
		return pgconn.CommandTag{}, db.err
	}
	if date.Time.After(db.latest.Time) {
		db.latest = date
	}
	return pgconn.CommandTag{}, nil
}

func TestRefreshDailySummary_FailedDayIsRetried(t *testing.T) {
	for _, daysAgo := range []int{2, 1} {
		t.Run(fmt.Sprintf("failed_%d_days_ago", daysAgo), func(t *testing.T) {
			log, _ := logrustest.NewNullLogger()
			today := time.Now().UTC().Truncate(24 * time.Hour)
			failedDay := today.AddDate(0, 0, -daysAgo).Format(time.DateOnly)
			writeErr := errors.New("daily snapshot storage unavailable")
			db := &dailySummaryDB{
				latest:   pgtype.Date{Time: today.AddDate(0, 0, -3), Valid: true},
				failDate: failedDay,
				attempts: make(map[string]int),
				err:      writeErr,
			}
			u := &Updater{
				querier: sql.New(db),
				log:     log.WithField("test", t.Name()),
			}

			require.ErrorIs(t, u.runRefreshDailySummary(t.Context()), writeErr)
			assert.Zero(t, db.attempts[today.Format(time.DateOnly)], "later days must not be written after a failed day")
			require.NoError(t, u.runRefreshDailySummary(t.Context()))
			require.Equal(t, 2, db.attempts[failedDay], "the missing snapshot day must be retried")
			require.Equal(t, 1, db.attempts[today.Format(time.DateOnly)])
		})
	}
}

type firstExecBlockingDB struct {
	sql.DBTX
	contexts []context.Context
}

func (db *firstExecBlockingDB) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	db.contexts = append(db.contexts, ctx)
	if len(db.contexts) == 1 {
		if _, ok := ctx.Deadline(); ok {
			<-ctx.Done()
		}
	}
	return pgconn.CommandTag{}, ctx.Err()
}

func (*firstExecBlockingDB) SendBatch(ctx context.Context, _ *pgx.Batch) pgx.BatchResults {
	return &contextBatchResults{ctx: ctx}
}

type contextBatchResults struct {
	pgx.BatchResults
	ctx context.Context
}

func (r *contextBatchResults) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, r.ctx.Err()
}

func (*contextBatchResults) Close() error { return nil }

type fetchMetricsSource struct {
	sources.Source
	err error
}

func (fetchMetricsSource) Name() string { return "metrics-test" }

func (s fetchMetricsSource) GetVulnerabilities(context.Context, string, string, bool) ([]*sources.Vulnerability, error) {
	return nil, s.err
}

func (fetchMetricsSource) MaintainSuppressedVulnerabilities(context.Context, []*sources.SuppressedVulnerability) error {
	return nil
}

type fetchMetricsDB struct{ sql.DBTX }

func (fetchMetricsDB) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), ctx.Err()
}

func (fetchMetricsDB) Query(ctx context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return emptyFetchRows{}, ctx.Err()
}

type emptyFetchRows struct{ pgx.Rows }

func (emptyFetchRows) Next() bool { return false }
func (emptyFetchRows) Err() error { return nil }
func (emptyFetchRows) Close()     {}

func TestFetchVulnerabilityDataForImages_RecordsOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name      string
		sourceErr error
		success   float64
		failed    float64
		queued    int
	}{
		{name: "success", success: 1, queued: 1},
		{name: "source_failure", sourceErr: errors.New("source unavailable"), failed: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			metrics.ResetUpdaterMetrics()
			t.Cleanup(metrics.ResetUpdaterMetrics)
			log, _ := logrustest.NewNullLogger()
			u := &Updater{
				source:  fetchMetricsSource{err: tt.sourceErr},
				querier: sql.New(fetchMetricsDB{}),
				log:     log.WithField("test", t.Name()),
			}
			ctx := NewDbContext(t.Context(), u.querier, u.log)
			ch := make(chan *ImageVulnerabilityData, 1)
			require.NoError(t, u.FetchVulnerabilityDataForImages(ctx, []*sql.Image{{Name: "image", Tag: "v1"}}, 1, ch))
			require.Len(t, ch, tt.queued)
			require.Equal(t, tt.success, updaterImageCount(t, "fetch", "success"))
			require.Equal(t, tt.failed, updaterImageCount(t, "fetch", "failed"))
		})
	}
}

type delayedSendBatchDB struct {
	failingSummaryDB
}

func (db *delayedSendBatchDB) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	time.Sleep(15 * time.Second)
	return db.failingSummaryDB.SendBatch(ctx, batch)
}

func TestBatchStageMetricsIncludeSendBatchWait(t *testing.T) {
	metrics.ResetUpdaterMetrics()
	t.Cleanup(metrics.ResetUpdaterMetrics)
	synctest.Test(t, func(t *testing.T) {
		log, _ := logrustest.NewNullLogger()
		u := &Updater{querier: sql.New(&delayedSendBatchDB{}), log: log.WithField("test", t.Name())}
		require.NoError(t, u.BatchUpdateVulnerabilityData(t.Context(), []*ImageVulnerabilityData{{ImageName: "image", ImageTag: "v1"}}))

		reg := prometheus.NewRegistry()
		reg.MustRegister(metrics.UpdaterStageDuration)
		families, err := reg.Gather()
		require.NoError(t, err)
		var samples int
		for _, family := range families {
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetName() == "stage" && label.GetValue() == "upsert_cves" {
						samples++
						require.Equal(t, uint64(1), metric.GetHistogram().GetSampleCount())
						require.Equal(t, 15.0, metric.GetHistogram().GetSampleSum(), "pool acquisition happens inside SendBatch")
					}
				}
			}
		}
		require.Equal(t, 1, samples)
	})
}

type partialImageStateDB struct {
	failingSummaryDB
	failAt   int
	rowErr   error
	closeErr error
}

func (db *partialImageStateDB) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	result := db.failingSummaryDB.SendBatch(ctx, batch)
	if db.nonEmptyBatches == 2 && batch.Len() > 0 {
		return &partialImageStateResults{failAt: db.failAt, rowErr: db.rowErr, closeErr: db.closeErr}
	}
	return result
}

type partialImageStateResults struct {
	pgx.BatchResults
	calls    int
	failAt   int
	rowErr   error
	closeErr error
}

func (r *partialImageStateResults) Exec() (pgconn.CommandTag, error) {
	r.calls++
	if r.calls == r.failAt {
		return pgconn.CommandTag{}, r.rowErr
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (r *partialImageStateResults) Close() error { return errors.Join(r.rowErr, r.closeErr) }

func TestBatchUpdateRecordsActualImageWriteOutcomes(t *testing.T) {
	summaryErr := errors.New("summary unavailable")
	rowErr := errors.New("image state write failed")
	closeErr := errors.New("image state commit failed")
	for _, tt := range []struct {
		name    string
		db      sql.DBTX
		success float64
		failed  float64
		err     error
	}{
		{name: "success", db: &failingSummaryDB{}, success: 2},
		{name: "summary_failure", db: &failingSummaryDB{failAt: 2, err: summaryErr}, failed: 2, err: summaryErr},
		{name: "partial_image_state_failure", db: &partialImageStateDB{failAt: 2, rowErr: rowErr}, failed: 2},
		{name: "image_state_close_failure", db: &partialImageStateDB{closeErr: closeErr}, failed: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			metrics.ResetUpdaterMetrics()
			t.Cleanup(metrics.ResetUpdaterMetrics)
			log, _ := logrustest.NewNullLogger()
			u := &Updater{querier: sql.New(tt.db), log: log.WithField("test", t.Name())}
			err := u.BatchUpdateVulnerabilityData(t.Context(), []*ImageVulnerabilityData{
				{ImageName: "first", ImageTag: "v1"},
				{ImageName: "second", ImageTag: "v1"},
			})
			require.Equal(t, tt.success, updaterImageCount(t, "write", "success"))
			require.Equal(t, tt.failed, updaterImageCount(t, "write", "failed"))
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func updaterImageCount(t *testing.T, stage, outcome string) float64 {
	t.Helper()
	metric := new(dto.Metric)
	require.NoError(t, metrics.UpdaterImages.WithLabelValues(stage, outcome).Write(metric))
	return metric.GetCounter().GetValue()
}

func TestUpdateContinuesAfterBatchWriteTimeout(t *testing.T) {
	t.Parallel()

	db := &firstExecBlockingDB{}
	u := NewUpdater(nil, nil, ScheduleConfig{}, nil, config.KevConfig{}, config.OsvConfig{})
	u.querier = sql.New(db)
	u.batchWriteTimeout = 100 * time.Millisecond

	ch := make(chan *ImageVulnerabilityData, 101)
	for range 101 {
		ch <- &ImageVulnerabilityData{ImageName: "image", ImageTag: "v1"}
	}
	close(ch)

	require.ErrorIs(t, u.Update(t.Context(), ch), context.DeadlineExceeded)
	firstDeadline, _ := db.contexts[0].Deadline()
	lastDeadline, _ := db.contexts[len(db.contexts)-1].Deadline()
	require.True(t, lastDeadline.After(firstDeadline))
}

func TestRunCycleSkipsWhenAlreadyRunning(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})

	u := &Updater{
		log: logrus.NewEntry(logrus.StandardLogger()),
	}
	u.cycle.step = func(context.Context) error {
		runs.Add(1)
		close(started)
		<-release
		return nil
	}

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- u.RunCycle(context.Background())
	}()

	<-started

	err := u.RunCycle(context.Background())
	require.NoError(t, err)

	close(release)
	require.NoError(t, <-firstDone)
	assert.Equal(t, int32(1), runs.Load())
}

func TestRunCycleReturnsStepError(t *testing.T) {
	t.Parallel()

	stepErr := errors.New("step failed")
	u := &Updater{
		log: logrus.NewEntry(logrus.StandardLogger()),
	}
	u.cycle.step = func(context.Context) error {
		return stepErr
	}

	err := u.RunCycle(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, stepErr)
}

func TestStartStopRunsConfiguredJobs(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32
	cfg := RuntimeConfig{
		Resync: JobRuntimeConfig{
			Enabled: true,
			Schedule: ScheduleConfig{
				Type:     SchedulerInterval,
				Interval: 10 * time.Millisecond,
			},
		},
	}

	u := NewUpdaterWithRuntimeConfig(
		nil,
		nil,
		logrus.NewEntry(logrus.StandardLogger()),
		config.KevConfig{},
		config.OsvConfig{},
		cfg,
	)
	u.cycle.step = func(context.Context) error {
		runs.Add(1)
		return nil
	}

	ctx := t.Context()

	u.Start(ctx)

	require.Eventually(t, func() bool {
		return runs.Load() > 0
	}, time.Second, 20*time.Millisecond)

	require.NoError(t, u.Stop(context.Background()))
	time.Sleep(40 * time.Millisecond)
	countSettled := runs.Load()
	time.Sleep(40 * time.Millisecond)
	assert.Equal(t, countSettled, runs.Load())
}

func TestStartDoesNotStartDisabledResyncJob(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32
	cfg := RuntimeConfig{
		Resync: JobRuntimeConfig{
			Enabled: false,
			Schedule: ScheduleConfig{
				Type:     SchedulerInterval,
				Interval: 10 * time.Millisecond,
			},
		},
		MarkUnused: JobRuntimeConfig{
			Enabled: true,
			Schedule: ScheduleConfig{
				Type:     SchedulerCron,
				CronExpr: "0 0 1 1 *",
			},
		},
	}

	u := NewUpdaterWithRuntimeConfig(
		nil,
		nil,
		logrus.NewEntry(logrus.StandardLogger()),
		config.KevConfig{},
		config.OsvConfig{},
		cfg,
	)
	u.cycle.step = func(context.Context) error {
		runs.Add(1)
		return nil
	}

	ctx := t.Context()

	u.Start(ctx)
	defer func() { _ = u.Stop(context.Background()) }()

	time.Sleep(80 * time.Millisecond)
	assert.Equal(t, int32(0), runs.Load())
	require.Len(t, u.lifecycle.jobs, 1)
	assert.Equal(t, "mark unused images", u.lifecycle.jobs[0].Name())
}

func TestNewRuntimeConfigUsesUpdaterConfig(t *testing.T) {
	resync := ScheduleConfig{Type: SchedulerInterval, Interval: time.Minute}
	cfg := NewRuntimeConfig(config.UpdaterConfig{
		ResyncEnabled:           true,
		MarkUnusedEnabled:       true,
		MarkUnusedCron:          "1 * * * *",
		MarkUntrackedCron:       "2 * * * *",
		RefreshSummaryCron:      "3 * * * *",
		RefreshLifetimesCron:    "4 * * * *",
		SyncKevEnabled:          true,
		SyncKevCron:             "5 * * * *",
		SyncOsvCron:             "6 * * * *",
		RekeySuppressedCron:     "7 * * * *",
		RefreshCveCountsEnabled: true,
		RefreshCveCountsCron:    "8 * * * *",
	}, resync)

	assert.Equal(t, JobRuntimeConfig{Enabled: true, Schedule: resync}, cfg.Resync)
	for name, test := range map[string]struct {
		job     JobRuntimeConfig
		enabled bool
		cron    string
	}{
		"MarkUnused":               {cfg.MarkUnused, true, "1 * * * *"},
		"MarkUntracked":            {cfg.MarkUntracked, false, "2 * * * *"},
		"RefreshDailySummary":      {cfg.RefreshDailySummary, false, "3 * * * *"},
		"RefreshWorkloadLifetimes": {cfg.RefreshWorkloadLifetimes, false, "4 * * * *"},
		"SyncKev":                  {cfg.SyncKev, true, "5 * * * *"},
		"SyncOsv":                  {cfg.SyncOsv, false, "6 * * * *"},
		"RekeySuppressedAliases":   {cfg.RekeySuppressedAliases, false, "7 * * * *"},
		"RefreshCveWorkloadCounts": {cfg.RefreshCveWorkloadCounts, true, "8 * * * *"},
	} {
		assert.Equal(t, JobRuntimeConfig{Enabled: test.enabled, Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: test.cron}}, test.job, name)
	}
}
