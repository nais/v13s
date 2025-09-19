package types

import (
	"time"

	"github.com/riverqueue/river"
)

const (
	KindFinalizeAttestation                      = "finalize_attestation"
	FinalizeAttestationScheduledForResyncMinutes = 1 * time.Minute
	FinalizeAttestationScheduledWaitSecond       = 30 * time.Second
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
		ScheduledAt: time.Now().Add(FinalizeAttestationScheduledWaitSecond),
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: FinalizeAttestationScheduledForResyncMinutes,
		},
		MaxAttempts: 15,
	}
}
