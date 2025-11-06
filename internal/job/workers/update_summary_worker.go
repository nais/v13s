package workers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job/jobs"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type UpsertVulnerabilitySummariesWorker struct {
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[jobs.UpsertVulnerabilitySummariesJob]
}

func (u *UpsertVulnerabilitySummariesWorker) Work(ctx context.Context, job *river.Job[jobs.UpsertVulnerabilitySummariesJob]) error {
	if len(job.Args.Images) == 0 {
		return nil
	}

	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)
	noProjectOrMetrics := 0

	for _, image := range job.Args.Images {
		summary, err := u.Source.GetVulnerabilitySummary(ctx, image.Name, image.Tag)
		if err != nil {
			if errors.Is(err, sources.ErrNoProject) || errors.Is(err, sources.ErrNoMetrics) {
				u.Log.WithField("image", image).Info("no vulnerability summary found")
				noProjectOrMetrics++
				continue
			}
			u.Log.WithError(err).WithField("image", image).Error("failed to get vulnerability summary")
			return err
		}

		if summary == nil {
			u.Log.WithField("image", image).Info("no vulnerability summary found")
			noProjectOrMetrics++
			continue
		}
		summaries = append(summaries, toVulnerabilitySummarySqlParams(image, summary))

		wls, err := u.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
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
	errorCount := 0
	u.Querier.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			u.Log.WithError(err).Errorf("failed to upsert summary %d", i)
			errorCount++
		}
	})

	duration := time.Since(start).Seconds()

	if noProjectOrMetrics > 0 {
		u.Log.WithField("count", noProjectOrMetrics).Info("images skipped due to no project or no metrics")
	}

	if errorCount > 0 {
		u.Log.WithFields(logrus.Fields{
			"num_rows":   len(summaries),
			"num_errors": errorCount,
			"duration":   duration,
		}).Error("failed to upsert some vulnerability summaries")
		return fmt.Errorf("%d vulnerability summaries failed to upsert", errorCount)
	}

	u.Log.WithFields(logrus.Fields{
		"num_rows": len(summaries),
		"duration": duration,
	}).Info("successfully upserted vulnerability summaries")
	jobs.RecordOutput(ctx, jobs.JobStatusSummariesUpdated)
	return nil
}

func toVulnerabilitySummarySqlParams(i jobs.Image, s *sources.VulnerabilitySummary) sql.BatchUpsertVulnerabilitySummaryParams {
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
