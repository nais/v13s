package jobs

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

const (
	KindGetAttestation = "get_attestation"
)

type GetAttestationJob struct {
	ImageName    string
	ImageTag     string
	WorkloadId   pgtype.UUID
	WorkloadType model.WorkloadType
}

func (GetAttestationJob) Kind() string { return KindGetAttestation }

func (g GetAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindGetAttestation,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 4,
	}
}
