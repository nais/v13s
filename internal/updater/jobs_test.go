package updater

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestScheduledJobsAreFailureIsolated(t *testing.T) {
	t.Parallel()

	var healthyRuns atomic.Int32
	healthyJob := newScheduledJob(
		"healthy",
		ScheduleConfig{Type: SchedulerInterval, Interval: 10 * time.Millisecond},
		logrus.NewEntry(logrus.StandardLogger()),
		func(context.Context) error {
			healthyRuns.Add(1)
			return nil
		},
	)
	failingJob := newScheduledJob(
		"failing",
		ScheduleConfig{Type: SchedulerInterval, Interval: 10 * time.Millisecond},
		logrus.NewEntry(logrus.StandardLogger()),
		func(context.Context) error {
			return errors.New("boom")
		},
	)

	ctx := t.Context()

	healthyJob.Start(ctx)
	failingJob.Start(ctx)
	defer func() {
		_ = healthyJob.Stop(context.Background())
		_ = failingJob.Stop(context.Background())
	}()

	require.Eventually(t, func() bool {
		return healthyRuns.Load() >= 2
	}, time.Second, 20*time.Millisecond)
}
