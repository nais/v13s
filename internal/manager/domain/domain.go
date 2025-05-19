package domain

import (
	"context"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/model"
)

type WorkloadService interface {
	AddWorkload(ctx context.Context, workload *model.Workload) error
	GetAttestation(ctx context.Context, workload *model.Workload, workloadId pgtype.UUID) error
	UploadAttestation(ctx context.Context, workload *model.Workload, workloadId pgtype.UUID, att *attestation.Attestation) error
	DeleteWorkload(ctx context.Context, w *model.Workload) error
}
