package types

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindFetchImage = "fetch_image"
)

type FetchImageJob struct {
	ImageName string
	ImageTag  string
}

func (FetchImageJob) Kind() string { return KindFetchImage }

func (FetchImageJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindFetchImage,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 6,
	}
}
