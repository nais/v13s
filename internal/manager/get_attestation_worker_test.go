package manager

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	mockattestation "github.com/nais/v13s/internal/mocks/Verifier"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

// stubJobClient is a no-op job.Client used in tests where job enqueueing is irrelevant.
type stubJobClient struct{}

func (s *stubJobClient) AddJob(_ context.Context, _ river.JobArgs) error { return nil }
func (s *stubJobClient) GetWorkers() *river.Workers                      { return river.NewWorkers() }
func (s *stubJobClient) Start(_ context.Context) error                   { return nil }
func (s *stubJobClient) Stop(_ context.Context) error                    { return nil }

// capturingJobClient records the enqueued job args for assertion.
type capturingJobClient struct {
	onAdd func(args river.JobArgs)
}

func (c *capturingJobClient) AddJob(_ context.Context, args river.JobArgs) error {
	if c.onAdd != nil {
		c.onAdd(args)
	}
	return nil
}
func (c *capturingJobClient) GetWorkers() *river.Workers    { return river.NewWorkers() }
func (c *capturingJobClient) Start(_ context.Context) error { return nil }
func (c *capturingJobClient) Stop(_ context.Context) error  { return nil }

func TestGetAttestationWorker_NoAttestation_IntermediateAttempt(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	verifier := mockattestation.NewMockVerifier(t)

	workloadId := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	imageName := "my-image"
	imageTag := "v1.0"

	// Verifier returns "no matching attestations" on this attempt
	verifier.EXPECT().GetAttestation(mock.Anything, fmt.Sprintf("%s:%s", imageName, imageTag)).
		Return(nil, &cosign.ErrNoMatchingAttestations{})

	// Workload state SHOULD be updated to no_attestation
	db.EXPECT().UpdateWorkloadState(mock.Anything, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateNoAttestation,
		ID:    workloadId,
	}).Return(nil)

	// Image state MUST NOT be updated (intermediate attempt — not final)
	// No call to UpdateImageState expected.
	worker := &GetAttestationWorker{
		db:              db,
		verifier:        verifier,
		jobClient:       &stubJobClient{},
		log:             logger,
		workloadCounter: noop.Int64UpDownCounter{},
	}

	// Attempt 1 of 4 — intermediate
	job := makeGetAttestationJob(1, 4, imageName, imageTag, workloadId)
	err := worker.Work(ctx, job)

	// Returns the cosign error so River schedules a retry
	require.Error(t, err)
	db.AssertExpectations(t)
	verifier.AssertExpectations(t)
}

func TestGetAttestationWorker_NoAttestation_FinalAttempt(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	verifier := mockattestation.NewMockVerifier(t)

	workloadId := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	imageName := "my-image"
	imageTag := "v1.0"

	verifier.EXPECT().GetAttestation(mock.Anything, fmt.Sprintf("%s:%s", imageName, imageTag)).
		Return(nil, &cosign.ErrNoMatchingAttestations{})

	// Workload → no_attestation
	db.EXPECT().UpdateWorkloadState(mock.Anything, sql.UpdateWorkloadStateParams{
		State: sql.WorkloadStateNoAttestation,
		ID:    workloadId,
	}).Return(nil)

	// Image → failed (final attempt only)
	db.EXPECT().UpdateImageState(mock.Anything, sql.UpdateImageStateParams{
		State: sql.ImageStateFailed,
		Name:  imageName,
		Tag:   imageTag,
	}).Return(int64(1), nil)

	worker := &GetAttestationWorker{
		db:              db,
		verifier:        verifier,
		jobClient:       &stubJobClient{},
		log:             logger,
		workloadCounter: noop.Int64UpDownCounter{},
	}

	// Attempt 4 of 4 — final
	job := makeGetAttestationJob(4, 4, imageName, imageTag, workloadId)
	err := worker.Work(ctx, job)

	require.Error(t, err)
	db.AssertExpectations(t)
	verifier.AssertExpectations(t)
}

func TestGetAttestationWorker_AttestationFound(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	verifier := mockattestation.NewMockVerifier(t)

	workloadId := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	imageName := "my-image"
	imageTag := "v1.0"

	att := &attestation.Attestation{Predicate: []byte(`{}`)}
	verifier.EXPECT().GetAttestation(mock.Anything, fmt.Sprintf("%s:%s", imageName, imageTag)).
		Return(att, nil)

	// No DB state changes expected — only upload is enqueued (via jobClient stub)

	enqueued := false
	jobClient := &capturingJobClient{onAdd: func(args river.JobArgs) {
		_, ok := args.(*UploadAttestationJob)
		assert.True(t, ok, "expected UploadAttestationJob to be enqueued")
		enqueued = true
	}}

	worker := &GetAttestationWorker{
		db:              db,
		verifier:        verifier,
		jobClient:       jobClient,
		log:             logger,
		workloadCounter: noop.Int64UpDownCounter{},
	}

	job := makeGetAttestationJob(1, 4, imageName, imageTag, workloadId)
	err := worker.Work(ctx, job)

	require.NoError(t, err)
	assert.True(t, enqueued, "expected upload_attestation job to be enqueued")
	db.AssertExpectations(t) // no DB calls expected
	verifier.AssertExpectations(t)
}

func makeGetAttestationJob(attempt, maxAttempts int, imageName, imageTag string, workloadId pgtype.UUID) *river.Job[GetAttestationJob] {
	return &river.Job[GetAttestationJob]{
		JobRow: &rivertype.JobRow{
			Attempt:     attempt,
			MaxAttempts: maxAttempts,
		},
		Args: GetAttestationJob{
			ImageName:  imageName,
			ImageTag:   imageTag,
			WorkloadId: workloadId,
		},
	}
}
