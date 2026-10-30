package updater

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

type batchUpdateDB struct {
	sql.DBTX
	failQuery string
	failValue string
	err       error
}

func (db *batchUpdateDB) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	name := strings.Fields(query)[2]
	if name == db.failQuery {
		for _, arg := range args {
			if value, ok := arg.(string); ok && value == db.failValue {
				return pgconn.CommandTag{}, db.err
			}
		}
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (*batchUpdateDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return &emptyBatchUpdateRows{}, nil
}

func (db *batchUpdateDB) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	return &batchUpdateResults{db: db, ctx: ctx, batch: batch}
}

type emptyBatchUpdateRows struct{ pgx.Rows }

func (*emptyBatchUpdateRows) Next() bool { return false }
func (*emptyBatchUpdateRows) Err() error { return nil }
func (*emptyBatchUpdateRows) Close()     {}

type batchUpdateResults struct {
	pgx.BatchResults
	db    *batchUpdateDB
	ctx   context.Context
	batch *pgx.Batch
	index int
}

func (r *batchUpdateResults) Exec() (pgconn.CommandTag, error) {
	query := r.batch.QueuedQueries[r.index]
	r.index++
	return r.db.Exec(r.ctx, query.SQL, query.Arguments...)
}

func (*batchUpdateResults) Close() error { return nil }

func TestBatchUpdateVulnerabilityDataLogsWriteFailures(t *testing.T) {
	t.Parallel()

	image := func(name string) *ImageVulnerabilityData {
		return &ImageVulnerabilityData{
			ImageName: "image-" + name,
			ImageTag:  "v1",
			Source:    "dependencytrack",
			Vulnerabilities: []*sources.Vulnerability{{
				Package: "pkg:maven/example@1",
				Cve: &sources.Cve{
					Id:         "CVE-" + name,
					Severity:   sources.SeverityHigh,
					References: map[string]string{"CVE-" + name: "GHSA-" + name},
				},
			}},
		}
	}

	for _, tt := range []struct {
		name      string
		failQuery string
		failValue string
		message   string
		fields    logrus.Fields
	}{
		{
			name: "CVEs", failQuery: "BatchUpsertCve", failValue: "CVE-failed",
			message: "batch row failed",
			fields:  logrus.Fields{"batch": "upsert CVEs", "cve_id": "CVE-failed"},
		},
		{
			name: "aliases", failQuery: "BatchUpsertCveAlias", failValue: "GHSA-failed",
			message: "batch row failed",
			fields:  logrus.Fields{"batch": "upsert CVE aliases", "cve_id": "CVE-failed", "alias": "GHSA-failed"},
		},
		{
			name: "findings", failQuery: "BatchUpsertVulnerabilities", failValue: "image-failed",
			message: "batch row failed",
			fields: logrus.Fields{
				"batch": "upsert vulnerabilities", "image": "image-failed", "tag": "v1",
				"source": "dependencytrack", "cve_id": "CVE-failed", "package": "pkg:maven/example@1",
			},
		},
		{
			name: "summary", failQuery: "RecalculateVulnerabilitySummary", failValue: "image-failed",
			message: "recalculate vulnerability summary",
			fields: logrus.Fields{
				"image": "image-failed", "tag": "v1", "source": "dependencytrack", "received_findings": 1,
			},
		},
		{
			name: "image state", failQuery: "BatchUpdateImageState", failValue: "image-failed",
			message: "batch row failed",
			fields:  logrus.Fields{"batch": "update image states", "image": "image-failed", "tag": "v1"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			writeErr := errors.New("database write failed")
			db := &batchUpdateDB{failQuery: tt.failQuery, failValue: tt.failValue, err: writeErr}
			log, hook := logrustest.NewNullLogger()
			u := &Updater{querier: sql.New(db), log: logrus.NewEntry(log)}

			err := u.BatchUpdateVulnerabilityData(t.Context(), []*ImageVulnerabilityData{
				image("healthy-before"), image("failed"), image("healthy-after"),
			})

			require.NoError(t, err)
			var entries []*logrus.Entry
			for _, entry := range hook.AllEntries() {
				if entry.Message == tt.message {
					entries = append(entries, entry)
				}
			}
			require.Len(t, entries, 1)
			assert.Equal(t, logrus.ErrorLevel, entries[0].Level)
			assert.Equal(t, writeErr, entries[0].Data[logrus.ErrorKey])
			for field, value := range tt.fields {
				assert.Equal(t, value, entries[0].Data[field], "log field %s", field)
			}
		})
	}
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
