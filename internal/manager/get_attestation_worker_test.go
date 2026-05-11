package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	attmock "github.com/nais/v13s/internal/mocks/Verifier"
	"github.com/nais/v13s/internal/model"
)

type stubJobClient struct{}

func (s *stubJobClient) AddJob(_ context.Context, _ river.JobArgs) error {
	return nil
}

func (s *stubJobClient) GetWorkers() *river.Workers    { return nil }
func (s *stubJobClient) Start(_ context.Context) error { return nil }
func (s *stubJobClient) Stop(_ context.Context) error  { return nil }

func makeGetAttestationJob(attempt, maxAttempts int) *river.Job[GetAttestationJob] {
	wid := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	return &river.Job[GetAttestationJob]{
		JobRow: &rivertype.JobRow{
			Attempt:     attempt,
			MaxAttempts: maxAttempts,
		},
		Args: GetAttestationJob{
			ImageName:  "myimage",
			ImageTag:   "v1",
			WorkloadId: wid,
		},
	}
}

func newGetAttestationWorker(t *testing.T, db *sqmock.MockQuerier, verifier *attmock.MockVerifier) *GetAttestationWorker {
	t.Helper()
	mp := otel.GetMeterProvider()
	noomp := noop.NewMeterProvider()
	_ = noomp
	counter, _ := mp.Meter("test").Int64UpDownCounter("workload_counter")
	return &GetAttestationWorker{
		db:              db,
		jobClient:       &stubJobClient{},
		verifier:        verifier,
		workloadCounter: counter,
		log:             logrus.NewEntry(logrus.New()),
	}
}

func TestGetAttestationWorker_ImageStateFailed_OnlyOnFinalAttempt(t *testing.T) {
	ctx := context.Background()

	t.Run("interim attempt: image state NOT set to failed", func(t *testing.T) {
		db := sqmock.NewMockQuerier(t)
		verifier := attmock.NewMockVerifier(t)

		verifier.EXPECT().GetAttestation(mock.Anything, "myimage:v1").Return(nil, model.ToUnrecoverableError(errors.New("permanent"), "attestation"))

		db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
			return p.State == sql.WorkloadStateUnrecoverable
		})).Return(nil)

		worker := newGetAttestationWorker(t, db, verifier)
		job := makeGetAttestationJob(1, 4)
		err := worker.Work(ctx, job)
		var cancelErr *rivertype.JobCancelError
		require.True(t, errors.As(err, &cancelErr), "expected river.JobCancelError, got: %v", err)
		db.AssertNotCalled(t, "UpdateImageState", mock.Anything, mock.Anything)
	})

	t.Run("final attempt: image state set to failed", func(t *testing.T) {
		db := sqmock.NewMockQuerier(t)
		verifier := attmock.NewMockVerifier(t)

		verifier.EXPECT().GetAttestation(mock.Anything, "myimage:v1").Return(nil, model.ToUnrecoverableError(errors.New("permanent"), "attestation"))

		db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
			return p.State == sql.WorkloadStateUnrecoverable
		})).Return(nil)

		db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
			return p.State == sql.ImageStateFailed
		})).Return(int64(1), nil)

		worker := newGetAttestationWorker(t, db, verifier)
		job := makeGetAttestationJob(4, 4)
		err := worker.Work(ctx, job)
		var cancelErr *rivertype.JobCancelError
		require.True(t, errors.As(err, &cancelErr), "expected river.JobCancelError, got: %v", err)
	})
}

func TestGetAttestationWorker_AttestationFound_EnqueuesUpload(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	verifier := attmock.NewMockVerifier(t)

	att := &attestation.Attestation{Predicate: []byte(`{}`)}
	verifier.EXPECT().GetAttestation(mock.Anything, "myimage:v1").Return(att, nil)

	worker := newGetAttestationWorker(t, db, verifier)
	job := makeGetAttestationJob(1, 4)
	err := worker.Work(ctx, job)
	require.NoError(t, err)
}
