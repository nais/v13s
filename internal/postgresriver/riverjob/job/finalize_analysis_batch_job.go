package job

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindFinalizeAnalysisBatch = "finalize_analysis_batch"
)

type FinalizeAnalysisBatchJob struct {
	Tokens []AnalysisTokenInfo
}

func (FinalizeAnalysisBatchJob) Kind() string { return KindFinalizeAnalysisBatch }

func (t FinalizeAnalysisBatchJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinalizeAnalysisBatch,
		ScheduledAt: time.Now().Add(5 * time.Second),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 2 * time.Minute,
		},
		MaxAttempts: 10,
	}
}

type AnalysisTokenInfo struct {
	ImageName, ImageTag, ProjectID, ProcessToken string
}
