package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

const (
	KindUpsertVulnerabilitySummaries   = "upsert_vulnerability_summaries"
	UpdateSummariesScheduledWaitSecond = 10 * time.Second
)

type Image struct {
	Name string
	Tag  string
}

type UpsertVulnerabilitySummariesJob struct {
	Images []Image
}

func (UpsertVulnerabilitySummariesJob) Kind() string {
	return KindUpsertVulnerabilitySummaries
}

func (u UpsertVulnerabilitySummariesJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		ScheduledAt: time.Now().Add(UpdateSummariesScheduledWaitSecond),
		Queue:       KindUpsertVulnerabilitySummaries,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 3,
	}
}

type UpsertVulnerabilitySummariesWorker struct {
	Db     sql.Querier
	Source sources.Source
	Log    logrus.FieldLogger
	river.WorkerDefaults[UpsertVulnerabilitySummariesJob]
}

func (u *UpsertVulnerabilitySummariesWorker) Work(ctx context.Context, job *river.Job[UpsertVulnerabilitySummariesJob]) error {
	if len(job.Args.Images) == 0 {
		return nil
	}

	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)
	for _, image := range job.Args.Images {
		summary, err := u.Source.GetVulnerabilitySummary(ctx, image.Name, image.Tag)
		if err != nil {
			if errors.Is(sources.ErrNoProject, err) || errors.Is(err, sources.ErrNoMetrics) {
				u.Log.WithField("image", image).Info("no vulnerability summary found")
				continue
			}
			u.Log.WithError(err).WithField("image", image).Error("failed to get vulnerability summary")
			return err
		}
		if summary == nil {
			u.Log.WithField("image", image).Info("no vulnerability summary found")
			continue
		}
		summaries = append(summaries, toVulnerabilitySummarySqlParams(image, summary))

		wls, err := u.Db.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
			ImageName: image.Name,
			ImageTag:  image.Tag,
		})
		if err != nil {
			u.Log.WithError(err).WithField("image", image).Error("failed to list workloads for image")
			return err
		}

		for _, wl := range wls {
			metrics.SetWorkloadMetrics(wl, summary)
		}
	}

	start := time.Now()
	errors := 0
	u.Db.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			u.Log.WithError(err).Errorf("failed to upsert summary %d", i)
			errors++
		}
	})

	duration := time.Since(start).Seconds()

	if errors > 0 {
		u.Log.WithFields(logrus.Fields{
			"num_rows":   len(summaries),
			"num_errors": errors,
			"duration":   duration,
		}).Error("failed to upsert some vulnerability summaries")
		return fmt.Errorf("%d vulnerability summaries failed to upsert", errors)
	}

	u.Log.WithFields(logrus.Fields{
		"num_rows": len(summaries),
		"duration": duration,
	}).Info("successfully upserted vulnerability summaries")
	recordOutput(ctx, JobStatusSummariesUpdated)
	return nil
}

func toVulnerabilitySummarySqlParams(i Image, s *sources.VulnerabilitySummary) sql.BatchUpsertVulnerabilitySummaryParams {
	return sql.BatchUpsertVulnerabilitySummaryParams{
		ImageName:  i.Name,
		ImageTag:   i.Tag,
		Critical:   s.Critical,
		High:       s.High,
		Medium:     s.Medium,
		Low:        s.Low,
		Unassigned: s.Unassigned,
		RiskScore:  s.RiskScore,
	}
}
