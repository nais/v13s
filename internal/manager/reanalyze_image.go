package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/nais/v13s/internal/sources"
	"github.com/riverqueue/river"
)

const (
	KindReanalyzeImage   = "reanalyze_image"
	KindFinishReanalysis = "finish_reanalysis"
	MaxReanalysisImages  = 250
)

var ErrReanalysisLimit = errors.New("too many images to reanalyze in one request")

type ReanalyzeImageJob struct {
	ImageName   string    `river:"unique"`
	ImageTag    string    `river:"unique"`
	ScheduledAt time.Time `json:"-"`
}

func (ReanalyzeImageJob) Kind() string { return KindReanalyzeImage }

func (j ReanalyzeImageJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindReanalyzeImage,
		ScheduledAt: j.ScheduledAt,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 10 * time.Minute,
		},
		MaxAttempts: 5,
	}
}

type ReanalyzeImageWorker struct {
	db        sql.Querier
	source    sources.Source
	jobClient job.Client
	river.WorkerDefaults[ReanalyzeImageJob]
}

func (w *ReanalyzeImageWorker) Work(ctx context.Context, j *river.Job[ReanalyzeImageJob]) error {
	output := JobOutput{
		Status:   "reanalysis_failed",
		Decision: "check_image_use",
		Details: map[string]string{
			"image": j.Args.ImageName,
			"tag":   j.Args.ImageTag,
		},
	}
	defer func() { recordStructuredOutput(ctx, output) }()

	active, err := w.db.ImageHasWorkload(ctx, sql.ImageHasWorkloadParams{
		ImageName: j.Args.ImageName, ImageTag: j.Args.ImageTag,
	})
	if err != nil {
		return fmt.Errorf("checking image use: %w", err)
	}
	if !active {
		output.Status = "reanalysis_skipped"
		output.Decision = "cancel_inactive_image"
		return river.JobCancel(fmt.Errorf("image no longer belongs to an active workload"))
	}
	output.Decision = "trigger_analysis"
	token, err := w.source.TriggerAnalysis(ctx, j.Args.ImageName, j.Args.ImageTag)
	if err != nil {
		return fmt.Errorf("triggering project analysis: %w", err)
	}
	if token == "" {
		return fmt.Errorf("project analysis returned empty process token")
	}
	output.Decision = "enqueue_completion"
	if err := w.jobClient.AddJob(ctx, &FinishReanalysisJob{
		ImageName: j.Args.ImageName, ImageTag: j.Args.ImageTag, ProcessToken: token,
	}); err != nil {
		return fmt.Errorf("enqueueing analysis completion: %w", err)
	}
	output.Status = "reanalysis_queued"
	output.Details["next_job"] = KindFinishReanalysis
	return nil
}

type FinishReanalysisJob struct {
	ImageName    string
	ImageTag     string
	ProcessToken string
}

func (FinishReanalysisJob) Kind() string { return KindFinishReanalysis }

func (FinishReanalysisJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinishReanalysis,
		ScheduledAt: time.Now().Add(10 * time.Second),
		MaxAttempts: 15,
	}
}

func (FinishReanalysisWorker) NextRetry(*river.Job[FinishReanalysisJob]) time.Time {
	return time.Now().Add(time.Minute)
}

type FinishReanalysisWorker struct {
	db     sql.Querier
	source sources.Source
	river.WorkerDefaults[FinishReanalysisJob]
}

func (w *FinishReanalysisWorker) Work(ctx context.Context, j *river.Job[FinishReanalysisJob]) error {
	inProgress, err := w.source.IsTaskInProgress(ctx, j.Args.ProcessToken)
	if err != nil {
		return fmt.Errorf("checking project analysis progress: %w", err)
	}
	if inProgress {
		recordStructuredOutput(ctx, JobOutput{
			Event:    string(EventTaskInProgress),
			Decision: "retry_later",
			Details: map[string]string{
				"image": j.Args.ImageName,
				"tag":   j.Args.ImageTag,
			},
		})
		return fmt.Errorf("project analysis is still in progress")
	}
	active, err := w.db.ImageHasWorkload(ctx, sql.ImageHasWorkloadParams{
		ImageName: j.Args.ImageName, ImageTag: j.Args.ImageTag,
	})
	if err != nil {
		return fmt.Errorf("checking image use: %w", err)
	}
	if !active {
		return river.JobCancel(fmt.Errorf("image no longer belongs to an active workload"))
	}
	updated, err := w.db.MarkImageForReanalysisResync(ctx, sql.MarkImageForReanalysisResyncParams{
		Name: j.Args.ImageName, Tag: j.Args.ImageTag,
	})
	if err != nil {
		return fmt.Errorf("marking analyzed image for resync: %w", err)
	}
	if updated == 0 {
		return river.JobCancel(fmt.Errorf("image no longer exists or has failed"))
	}
	recordStructuredOutput(ctx, JobOutput{
		Status:   "reanalysis_ready_for_resync",
		Event:    string(EventTaskComplete),
		Decision: "mark_resync",
		Details: map[string]string{
			"image": j.Args.ImageName,
			"tag":   j.Args.ImageTag,
		},
	})
	return nil
}
