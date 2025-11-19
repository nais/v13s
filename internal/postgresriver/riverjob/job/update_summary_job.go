package job

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindUpsertVulnerabilitySummaries = "upsert_vulnerability_summaries"
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
		Queue: KindUpsertVulnerabilitySummaries,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 3,
	}
}
