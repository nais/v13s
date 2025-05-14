package manager

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

type AddWorkloadArgs struct {
	Workload *model.Workload
}

func (AddWorkloadArgs) Kind() string { return "addWorkload" }

type AddWorkloadWorker struct {
	river.WorkerDefaults[AddWorkloadArgs]
}

func (w *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadArgs]) error {
	fmt.Printf("working workload: %+v\n", job.Args.Workload)
	return nil
}

type GetAttestationArgs struct {
	ImageName string
	ImageTag  string
}

func (GetAttestationArgs) Kind() string { return "getAttestation" }

type UploadAttestationArgs struct {
	WorkloadId pgtype.UUID
	Workload   *model.Workload
	Att        *attestation.Attestation
}

func (UploadAttestationArgs) Kind() string { return "uploadAttestation" }
