package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/job"
	"github.com/riverqueue/river"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	KindGetAttestation = "get_attestation"
)

type GetAttestationJob struct {
	ImageName  string
	ImageTag   string
	WorkloadId pgtype.UUID
}

func (GetAttestationJob) Kind() string { return KindGetAttestation }

func (g GetAttestationJob) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: KindGetAttestation,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 1 * time.Minute,
		},
		//	Tags:  []string{g.ImageTag},
	}
}

type GetAttestationWorker struct {
	db              sql.Querier
	jobClient       job.Client
	verifier        attestation.Verifier
	workloadCounter metric.Int64UpDownCounter
	log             logrus.FieldLogger
	river.WorkerDefaults[GetAttestationJob]
}

func (g *GetAttestationWorker) Work(ctx context.Context, job *river.Job[GetAttestationJob]) error {
	imageName := job.Args.ImageName
	imageTag := job.Args.ImageTag
	att, err := g.verifier.GetAttestation(ctx, fmt.Sprintf("%s:%s", imageName, imageTag))
	g.workloadCounter.Add(
		ctx,
		1,
		metric.WithAttributes(
			attribute.String("hasAttestation", fmt.Sprint(att != nil)),
		))

	if err != nil {
		var noMatchAttestationError *cosign.ErrNoMatchingAttestations
		// TODO: handle no attestation found vs error in verifying
		if errors.As(err, &noMatchAttestationError) {
			if err.Error() != "no matching attestations: " {
				g.log.WithError(err).Error("failed to get attestation")
			}
			// TODO: handle errors
			err = g.db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
				State: sql.WorkloadStateNoAttestation,
				ID:    job.Args.WorkloadId,
			})
			if err != nil {
				return fmt.Errorf("failed to set workload state: %w", err)
			}
			recordOutput(ctx, JobStatusNoAttestation)
			return river.JobCancel(err)
		} else {
			return handleJobErr(err)
		}
	}
	if att != nil {
		compressed, err := att.Compress()
		if err != nil {
			return fmt.Errorf("failed to compress attestation: %w", err)
		}
		err = g.jobClient.AddJob(ctx, &UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  job.Args.WorkloadId,
			Attestation: compressed,
		})
		if err != nil {
			return err
		}
		recordOutput(ctx, JobStatusNoAttestation)
	}
	return nil
}
