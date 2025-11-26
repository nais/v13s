package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/riverupdater/riverjob"
	"github.com/nais/v13s/internal/riverupdater/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type UpsertVulnerabilitySummariesWorker struct {
	Querier sql.Querier
	Source  sources.Source
	Log     logrus.FieldLogger
	river.WorkerDefaults[job.UpsertVulnerabilitySummariesJob]
}

func (u *UpsertVulnerabilitySummariesWorker) Work(ctx context.Context, j *river.Job[job.UpsertVulnerabilitySummariesJob]) error {
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	if len(j.Args.Images) == 0 {
		rec.Add("start", "ok", "no_images")
		rec.Add("finish", "success", "")
		return nil
	}

	imgCount := len(j.Args.Images)
	rec.Add("start", "ok", fmt.Sprintf("images=%d", imgCount))

	summaries := make([]sql.BatchUpsertVulnerabilitySummaryParams, 0)
	noProjectOrMetrics := 0
	fetchErrCount := 0
	listErrCount := 0
	upsertErrCount := 0

	// Summary fetch phase
	for _, image := range j.Args.Images {
		summary, err := u.Source.GetVulnerabilitySummary(ctx, image.Name, image.Tag)
		if err != nil {
			if errors.Is(err, sources.ErrNoProject) || errors.Is(err, sources.ErrNoMetrics) {
				noProjectOrMetrics++
				continue
			}
			fetchErrCount++
			u.Log.WithError(err).WithField("image", image).Error("failed to get vulnerability summary")
			continue
		}

		if summary == nil {
			noProjectOrMetrics++
			continue
		}

		summaries = append(summaries, toVulnerabilitySummarySqlParams(image, summary))

		// List workloads
		wls, err := u.Querier.ListWorkloadsByImage(ctx, sql.ListWorkloadsByImageParams{
			ImageName: image.Name,
			ImageTag:  image.Tag,
		})
		if err != nil {
			listErrCount++
			u.Log.WithError(err).WithField("image", image).Error("failed to list workloads for image")
			continue
		}

		for _, wl := range wls {
			metrics.SetWorkloadMetrics(wl, summary)
		}
	}

	rec.Add("summary", "ok",
		fmt.Sprintf(
			"summaries=%d skipped=%d fetch_errors=%d list_errors=%d",
			len(summaries),
			noProjectOrMetrics,
			fetchErrCount,
			listErrCount,
		),
	)

	// Upsert summaries
	rec.Add("upsert_summaries", "start", fmt.Sprintf("rows=%d", len(summaries)))
	start := time.Now()
	u.Querier.BatchUpsertVulnerabilitySummary(ctx, summaries).Exec(func(i int, err error) {
		if err != nil {
			upsertErrCount++
			u.Log.WithError(err).Errorf("failed to upsert summary %d", i)
		}
	})
	dur := time.Since(start).Seconds()

	if noProjectOrMetrics > 0 {
		u.Log.WithField("count", noProjectOrMetrics).Debug("images skipped due to no project or metrics")
	}

	if upsertErrCount > 0 {
		rec.Add("upsert_summaries", "error", fmt.Sprintf("errors=%d", upsertErrCount))
		u.Log.WithFields(logrus.Fields{
			"num_rows":   len(summaries),
			"num_errors": upsertErrCount,
			"duration":   dur,
		}).Error("failed to upsert some vulnerability summaries")

		rec.Add("finish", "error", fmt.Sprintf("errors=%d", upsertErrCount))
		return fmt.Errorf("%d vulnerability summaries failed to upsert", upsertErrCount)
	}

	rec.Add("upsert_summaries", "ok", fmt.Sprintf("duration=%.3fs", dur))

	u.Log.WithFields(logrus.Fields{
		"num_rows": len(summaries),
		"duration": dur,
	}).Debug("successfully upserted vulnerability summaries")

	rec.Add("finish", "success", "")
	riverjob.RecordOutput(ctx, riverjob.JobStatusSummariesUpdated)
	return nil
}

func toVulnerabilitySummarySqlParams(i job.Image, s *sources.VulnerabilitySummary) sql.BatchUpsertVulnerabilitySummaryParams {
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
