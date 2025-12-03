package job

import (
	"time"

	"github.com/nais/v13s/internal/riverupdater/riverjob/domain"
	"github.com/riverqueue/river"
)

const (
	KindUpsertVulnerabilitySummaries = "upsert_vulnerability_summaries"
)

type UpsertVulnerabilitySummariesJob struct {
	Images []domain.Image
}

func (UpsertVulnerabilitySummariesJob) Kind() string {
	return KindUpsertVulnerabilitySummaries
}

func (u UpsertVulnerabilitySummariesJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindUpsertVulnerabilitySummaries,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 3,
	}
}
