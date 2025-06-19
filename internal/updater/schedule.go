package updater

import (
	"context"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
)

type SchedulerType int

const (
	SchedulerCron SchedulerType = iota
	SchedulerInterval
)

// ScheduleConfig holds schedule configuration either as cron or interval
type ScheduleConfig struct {
	Type     SchedulerType
	CronExpr string
	Interval time.Duration
}

func runScheduled(ctx context.Context, schedule ScheduleConfig, name string, log *logrus.Entry, job func()) {
	switch schedule.Type {
	case SchedulerCron:
		runAtCronSchedule(ctx, schedule.CronExpr, name, log, job)
	case SchedulerInterval:
		runAtInterval(ctx, schedule.Interval, name, log, job)
	default:
		log.Errorf("unknown schedule type for job '%s'", name)
	}
}

func runAtInterval(ctx context.Context, interval time.Duration, name string, log *logrus.Entry, job func()) {
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Infof("job '%s' stopped", name)
				return
			case <-ticker.C:
				log.Infof("running scheduled job '%s'", name)
				job()
			}
		}
	}()
}

func runAtCronSchedule(ctx context.Context, cronExpr string, name string, log *logrus.Entry, job func()) {
	location, err := time.LoadLocation("Europe/Oslo")
	if err != nil {
		log.WithError(err).Error("failed to load time zone")
		return
	}

	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		log.WithError(err).Errorf("invalid cron expression for job '%s': %s", name, cronExpr)
		return
	}

	log.Infof("job '%s' scheduled with cron '%s'", name, cronExpr)
	logNextCronRun(log, name, schedule, location, time.Now())

	c := cron.New(cron.WithLocation(location))

	_, err = c.AddFunc(cronExpr, func() {
		select {
		case <-ctx.Done():
			log.Infof("job '%s' stopped", name)
			return
		default:
			now := time.Now()
			logNextCronRun(log, name, schedule, location, now)
			job()
		}
	})
	if err != nil {
		log.WithError(err).Errorf("failed to schedule job '%s' with cron '%s'", name, cronExpr)
		return
	}

	go func() {
		<-ctx.Done()
		log.Infof("stopping cron scheduler for job '%s'", name)
		c.Stop()
	}()

	c.Start()
}

func logNextCronRun(log *logrus.Entry, name string, schedule cron.Schedule, location *time.Location, now time.Time) {
	next := schedule.Next(now.In(location))
	log.Infof("running scheduled job '%s' at %s (%s), next run at %s",
		name,
		now.Format(time.RFC3339),
		location.String(),
		next.Format(time.RFC3339),
	)
}
