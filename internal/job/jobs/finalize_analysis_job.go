package jobs

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindFinalizeAnalysis       = "finalize_analysis"
	TriggerAnalysisMaxAttempts = 10
)

type FinalizeAnalysisJob struct {
	ProjectID    string `river:"unique"`
	ImageName    string
	ImageTag     string
	ProcessToken string
}

func (FinalizeAnalysisJob) Kind() string { return KindFinalizeAnalysis }

func (t FinalizeAnalysisJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinalizeAnalysis,
		ScheduledAt: time.Now().Add(5 * time.Second),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 2 * time.Minute,
		},
		MaxAttempts: TriggerAnalysisMaxAttempts,
	}
}
