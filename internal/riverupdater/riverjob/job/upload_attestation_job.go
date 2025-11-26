package job

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

const (
	KindUploadAttestation = "upload_attestation"
)

type UploadAttestationJob struct {
	ImageName   string `river:"unique"`
	ImageTag    string `river:"unique"`
	WorkloadId  pgtype.UUID
	Attestation []byte
}

func (UploadAttestationJob) Kind() string { return KindUploadAttestation }

func (u UploadAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindUploadAttestation,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		MaxAttempts: 8,
	}
}
