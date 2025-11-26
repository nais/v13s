package job

import (
	"time"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

const (
	KindAddWorkload = "add_workload"
)

type AddWorkloadJob struct {
	Workload *model.Workload
}

func (AddWorkloadJob) Kind() string { return KindAddWorkload }

func (a AddWorkloadJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		Queue:       KindAddWorkload,
		MaxAttempts: 4,
	}
}
