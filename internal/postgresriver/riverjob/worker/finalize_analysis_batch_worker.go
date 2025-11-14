package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/nais/v13s/internal/postgresriver/riverjob"
	"github.com/nais/v13s/internal/postgresriver/riverjob/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
)

type FinalizeAnalysisBatchWorker struct {
	Source    sources.Source
	JobClient riverjob.Client
	Log       logrus.FieldLogger
	river.WorkerDefaults[job.FinalizeAnalysisBatchJob]
}

func (f *FinalizeAnalysisBatchWorker) Work(ctx context.Context, j *river.Job[job.FinalizeAnalysisBatchJob]) error {
	ctx = riverjob.NewRecorder(ctx)
	rec := riverjob.FromContext(ctx)
	defer rec.Flush(ctx)

	total := len(j.Args.Tokens)
	rec.Add("start", "ok", fmt.Sprintf("token_count=%d", total))

	var remaining []job.AnalysisTokenInfo
	var done []*sources.ImageVulnerabilityData

	inProgressCount := 0
	fetchErrCount := 0

	for _, t := range j.Args.Tokens {
		inProgress, err := f.Source.IsTaskInProgress(ctx, t.ProcessToken)
		if err != nil {
			inProgressCount++
			remaining = append(remaining, t)
			continue
		}

		if inProgress {
			inProgressCount++
			remaining = append(remaining, t)
			continue
		}

		vulns, err := f.Source.GetVulnerabilities(ctx, t.ImageName, t.ImageTag, true)
		if err != nil {
			if errors.Is(err, sources.ErrNoProject) || errors.Is(err, sources.ErrNoMetrics) {
				rec.Add("get_vulnerabilities", "skipped", fmt.Sprintf("no_project_or_metrics for %s:%s", t.ImageName, t.ImageTag))
				continue
			}
			fetchErrCount++
			remaining = append(remaining, t)
			continue
		}

		done = append(done, &sources.ImageVulnerabilityData{
			ImageName:       t.ImageName,
			ImageTag:        t.ImageTag,
			Source:          f.Source.Name(),
			Vulnerabilities: vulns,
		})
	}

	rec.Add("analysis_results", "ok",
		fmt.Sprintf("done=%d in_progress=%d errors=%d", len(done), inProgressCount, fetchErrCount),
	)

	// Re-enqueue unfinished ones
	if len(remaining) > 0 {
		rec.Add("enqueue_finalize_again", "start", fmt.Sprintf("remaining=%d", len(remaining)))
		if err := f.JobClient.AddJob(ctx, &job.FinalizeAnalysisBatchJob{
			Tokens: remaining,
		}); err != nil {
			rec.Add("enqueue_finalize_again", "error", err.Error())
			return fmt.Errorf("re-enqueue finalize batch: %w", err)
		}
		rec.Add("enqueue_finalize_again", "ok", "")
	}

	// Enqueue completed batches for processing
	if len(done) > 0 {
		rec.Add("enqueue_process_batch", "start", fmt.Sprintf("batches=%d", len(done)))
		if err := f.JobClient.AddJob(ctx, &job.ProcessVulnerabilityDataBatchJob{
			Batches: done,
		}); err != nil {
			rec.Add("enqueue_process_batch", "error", err.Error())
			return fmt.Errorf("enqueue process batch: %w", err)
		}
		rec.Add("enqueue_process_batch", "ok", "")
	}

	rec.Add("finish", "success", "")
	return nil
}
