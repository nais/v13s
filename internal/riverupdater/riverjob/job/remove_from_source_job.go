package job

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindRemoveFromSource = "remove_from_source"
)

type RemoveFromSourceJob struct {
	ImageName string `json:"image_name" river:"unique"`
	ImageTag  string `json:"image_tag" river:"unique"`
}

func (RemoveFromSourceJob) Kind() string { return KindRemoveFromSource }

func (u RemoveFromSourceJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindRemoveFromSource,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 2 * time.Minute,
		},
		MaxAttempts: 8,
	}
}
