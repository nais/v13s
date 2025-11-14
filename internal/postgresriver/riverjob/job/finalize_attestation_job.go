package job

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindFinalizeAttestation = "finalize_attestation"
)

type FinalizeAttestationJob struct {
	ImageName    string `river:"unique"`
	ImageTag     string `river:"unique"`
	ProcessToken string
}

func (FinalizeAttestationJob) Kind() string { return KindFinalizeAttestation }

func (f FinalizeAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       KindFinalizeAttestation,
		ScheduledAt: time.Now().Add(10 * time.Second),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 15,
	}
}
