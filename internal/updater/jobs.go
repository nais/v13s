package updater

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Job interface {
	Name() string
	Start(ctx context.Context)
	Stop(ctx context.Context) error
}

type JobRuntimeConfig struct {
	Enabled  bool
	Schedule ScheduleConfig
}

type RuntimeConfig struct {
	Resync                   JobRuntimeConfig
	MarkUnused               JobRuntimeConfig
	MarkUntracked            JobRuntimeConfig
	RefreshDailySummary      JobRuntimeConfig
	RefreshWorkloadLifetimes JobRuntimeConfig
	SyncKev                  JobRuntimeConfig
	SyncOsv                  JobRuntimeConfig
	RekeySuppressedAliases   JobRuntimeConfig
	RefreshCveWorkloadCounts JobRuntimeConfig
	CleanupUnusedImages      CleanupUnusedImagesConfig
}

type CleanupUnusedImagesConfig struct {
	JobRuntimeConfig
	Retention time.Duration
	BatchSize int32
}

func DefaultRuntimeConfig(resyncSchedule ScheduleConfig) RuntimeConfig {
	return RuntimeConfig{
		Resync: JobRuntimeConfig{
			Enabled:  true,
			Schedule: resyncSchedule,
		},
		MarkUnused: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUnusedCronInterval},
		},
		MarkUntracked: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: MarkUntrackedCronInterval},
		},
		RefreshDailySummary: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshVulnerabilitySummaryCronDailyView},
		},
		RefreshWorkloadLifetimes: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshWorkloadVulnerabilityLifetimesCronDailyView},
		},
		SyncKev: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: SyncKevCronInterval},
		},
		SyncOsv: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: SyncOsvCronInterval},
		},
		RekeySuppressedAliases: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: RekeySuppressedAliasesCronInterval},
		},
		RefreshCveWorkloadCounts: JobRuntimeConfig{
			Enabled:  true,
			Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: RefreshCveWorkloadCountsCronInterval},
		},
		CleanupUnusedImages: CleanupUnusedImagesConfig{
			JobRuntimeConfig: JobRuntimeConfig{
				Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: "0 3 * * *"},
			},
			Retention: 60 * 24 * time.Hour,
			BatchSize: 1000,
		},
	}
}

type scheduledJob struct {
	name     string
	schedule ScheduleConfig
	log      *logrus.Entry
	run      func(context.Context) error

	mu     sync.Mutex
	cancel context.CancelFunc
}

func newScheduledJob(name string, schedule ScheduleConfig, log *logrus.Entry, run func(context.Context) error) Job {
	return &scheduledJob{
		name:     name,
		schedule: schedule,
		log:      log,
		run:      run,
	}
}

func (j *scheduledJob) Name() string {
	return j.name
}

func (j *scheduledJob) Start(ctx context.Context) {
	jobCtx, cancel := context.WithCancel(ctx)
	j.mu.Lock()
	if j.cancel != nil {
		j.cancel()
	}
	j.cancel = cancel
	j.mu.Unlock()

	runScheduled(jobCtx, j.schedule, j.name, j.log, func() {
		if err := j.run(jobCtx); err != nil {
			j.log.WithError(err).Errorf("scheduled job '%s' failed", j.name)
		}
	})
}

func (j *scheduledJob) Stop(_ context.Context) error {
	j.mu.Lock()
	cancel := j.cancel
	j.cancel = nil
	j.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}
