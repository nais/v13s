package workers

import (
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/manager/domain"

	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
)

type AddWorkloadArgs struct {
	Workload *model.Workload
}

func (AddWorkloadArgs) Kind() string { return "addWorkload" }

type AddWorkloadWorker struct {
	river.WorkerDefaults[AddWorkloadArgs]
	Svc domain.WorkloadService
}

func (w *AddWorkloadWorker) Work(ctx context.Context, job *river.Job[AddWorkloadArgs]) error {
	return w.Svc.AddWorkload(ctx, job.Args.Workload)
}

type GetAttestationArgs struct {
	Workload   *model.Workload
	WorkloadId pgtype.UUID
}

func (GetAttestationArgs) Kind() string { return "getAttestation" }

type GetAttestationWorker struct {
	river.WorkerDefaults[GetAttestationArgs]
	Svc domain.WorkloadService
}

func (w *GetAttestationWorker) Work(ctx context.Context, job *river.Job[GetAttestationArgs]) error {
	return w.Svc.GetAttestation(ctx, job.Args.Workload, job.Args.WorkloadId)
}

type UploadAttestationArgs struct {
	Workload   *model.Workload
	WorkloadId pgtype.UUID
	Att        *attestation.Attestation
}

func (UploadAttestationArgs) Kind() string { return "uploadAttestation" }

type UploadAttestationWorker struct {
	river.WorkerDefaults[UploadAttestationArgs]
	Svc domain.WorkloadService
}

func (w *UploadAttestationWorker) Work(ctx context.Context, job *river.Job[UploadAttestationArgs]) error {
	return w.Svc.UploadAttestation(ctx, job.Args.Workload, job.Args.WorkloadId, job.Args.Att)
}
