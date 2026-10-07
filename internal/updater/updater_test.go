package updater

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
