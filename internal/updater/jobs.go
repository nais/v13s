package updater

import (
	"context"
	"sync"

	"github.com/nais/v13s/internal/config"
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
}

func NewRuntimeConfig(cfg config.UpdaterConfig, resync ScheduleConfig) RuntimeConfig {
	cron := func(enabled bool, expr string) JobRuntimeConfig {
		return JobRuntimeConfig{Enabled: enabled, Schedule: ScheduleConfig{Type: SchedulerCron, CronExpr: expr}}
	}
	return RuntimeConfig{
		Resync:                   JobRuntimeConfig{Enabled: cfg.ResyncEnabled, Schedule: resync},
		MarkUnused:               cron(cfg.MarkUnusedEnabled, cfg.MarkUnusedCron),
		MarkUntracked:            cron(cfg.MarkUntrackedEnabled, cfg.MarkUntrackedCron),
		RefreshDailySummary:      cron(cfg.RefreshSummaryEnabled, cfg.RefreshSummaryCron),
		RefreshWorkloadLifetimes: cron(cfg.RefreshLifetimesEnabled, cfg.RefreshLifetimesCron),
		SyncKev:                  cron(cfg.SyncKevEnabled, cfg.SyncKevCron),
		SyncOsv:                  cron(cfg.SyncOsvEnabled, cfg.SyncOsvCron),
		RekeySuppressedAliases:   cron(cfg.RekeySuppressedEnabled, cfg.RekeySuppressedCron),
		RefreshCveWorkloadCounts: cron(cfg.RefreshCveCountsEnabled, cfg.RefreshCveCountsCron),
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
