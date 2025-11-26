package job

import (
	"github.com/nais/v13s/internal/riverupdater/riverjob/domain"
	"github.com/riverqueue/river"
)

const (
	KindFinalizeAnalysisBatch = "finalize_analysis_batch"
)

type FinalizeAnalysisBatchJob struct {
	Tokens []domain.AnalysisTokenInfo
}

func (FinalizeAnalysisBatchJob) Kind() string { return KindFinalizeAnalysisBatch }

func (t FinalizeAnalysisBatchJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinalizeAnalysisBatch,
		MaxAttempts: 3,
	}
}
