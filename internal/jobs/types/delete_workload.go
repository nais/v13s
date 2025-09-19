package types

import (
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

const (
	KindDeleteWorkload = "delete_workload"
)

type DeleteWorkloadJob struct {
	Workload *model.Workload
}

func (DeleteWorkloadJob) Kind() string { return KindDeleteWorkload }

func (u DeleteWorkloadJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindDeleteWorkload,
		MaxAttempts: 4,
	}
}
