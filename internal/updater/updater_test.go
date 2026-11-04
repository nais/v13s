package updater

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
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
