package job

import (
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
		MaxAttempts: 3,
	}
}

type AnalysisTokenInfo struct {
	ImageName, ImageTag, ProjectID, ProcessToken string
}
