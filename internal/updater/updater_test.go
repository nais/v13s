package updater

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// safeBuffer wraps bytes.Buffer with a mutex to allow concurrent reads and
// writes from test goroutines and the updater's background goroutines.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newBufferedLogger(buf *safeBuffer) *logrus.Entry {
	logger := logrus.New()
	logger.SetOutput(buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
	return logrus.NewEntry(logger)
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
		OrchestrationEnabled: true,
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

func TestStartUsesLegacyJobsWhenOrchestrationDisabled(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32
	var logs safeBuffer
	cfg := RuntimeConfig{
		OrchestrationEnabled: false,
		Resync: JobRuntimeConfig{
			// Legacy orchestration always schedules the resync job, even when this flag is false.
			Enabled: false,
			Schedule: ScheduleConfig{
				Type:     SchedulerInterval,
				Interval: 10 * time.Millisecond,
			},
		},
	}

	u := NewUpdaterWithRuntimeConfig(
		nil,
		nil,
		newBufferedLogger(&logs),
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
	assert.Contains(t, logs.String(), "\"mode\":\"legacy\"")
	require.Eventually(t, func() bool {
		return runs.Load() > 0
	}, time.Second, 20*time.Millisecond)
	require.NoError(t, u.Stop(context.Background()))
}

func TestStartUsesRuntimeOrchestrationWhenEnabled(t *testing.T) {
	t.Parallel()

	var logs safeBuffer
	cfg := RuntimeConfig{
		OrchestrationEnabled: true,
		Resync: JobRuntimeConfig{
			Enabled: false,
			Schedule: ScheduleConfig{
				Type:     SchedulerInterval,
				Interval: 10 * time.Millisecond,
			},
		},
	}

	u := NewUpdaterWithRuntimeConfig(
		nil,
		nil,
		newBufferedLogger(&logs),
		config.KevConfig{},
		config.OsvConfig{},
		cfg,
	)

	u.Start(t.Context())
	defer func() { _ = u.Stop(context.Background()) }()

	assert.Contains(t, logs.String(), "starting updater jobs with runtime orchestration")
	assert.Contains(t, logs.String(), "\"mode\":\"runtime\"")
}

func TestStartDoesNotStartDisabledResyncJob(t *testing.T) {
	t.Parallel()

	var runs atomic.Int32
	cfg := RuntimeConfig{
		OrchestrationEnabled: true,
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
