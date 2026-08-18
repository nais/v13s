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
	"github.com/nais/v13s/internal/sources"
)

type stubJobClient struct{}

func (s *stubJobClient) AddJob(_ context.Context, _ river.JobArgs) error {
	return nil
}

func (s *stubJobClient) GetWorkers() *river.Workers    { return nil }
func (s *stubJobClient) Start(_ context.Context) error { return nil }
func (s *stubJobClient) Stop(_ context.Context) error  { return nil }

type recordingJobClient struct {
	jobs []river.JobArgs
}

func (c *recordingJobClient) AddJob(_ context.Context, args river.JobArgs) error {
	c.jobs = append(c.jobs, args)
	return nil
}
func (c *recordingJobClient) GetWorkers() *river.Workers    { return nil }
func (c *recordingJobClient) Start(_ context.Context) error { return nil }
func (c *recordingJobClient) Stop(_ context.Context) error  { return nil }

func testSources(t *testing.T, active sources.Source) *sources.Sources {
	t.Helper()
	sourceSet, err := sources.NewSet(active)
	require.NoError(t, err)
	return sourceSet
}

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
	sources := testSources(t, &sourceStub{identity: sources.Identity{Type: "dependencytrack", Instance: "test-source"}})
	return &GetAttestationWorker{
		db:              db,
		jobClient:       &stubJobClient{},
		verifier:        verifier,
		sources:         sources,
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

func TestGetAttestationWorker_AttestationFound_EnqueuesUploadForEachWriteTarget(t *testing.T) {
	ctx := context.Background()
	db := sqmock.NewMockQuerier(t)
	verifier := attmock.NewMockVerifier(t)
	verifier.EXPECT().GetAttestation(mock.Anything, "myimage:v1").Return(&attestation.Attestation{Predicate: []byte(`{}`)}, nil)

	v4 := &sourceStub{identity: sources.Identity{Type: "dependencytrack", Instance: "dt-v4"}}
	v5 := &sourceStub{identity: sources.Identity{Type: "dependencytrack", Instance: "dt-v5"}}
	sourceSet, err := sources.NewSet(v4, v5)
	require.NoError(t, err)

	jobClient := &recordingJobClient{}
	worker := newGetAttestationWorker(t, db, verifier)
	worker.jobClient = jobClient
	worker.sources = sourceSet

	require.NoError(t, worker.Work(ctx, makeGetAttestationJob(1, 4)))
	require.Len(t, jobClient.jobs, 2)

	instances := make([]string, 0, 2)
	for _, args := range jobClient.jobs {
		upload, ok := args.(*UploadAttestationJob)
		require.True(t, ok)
		instances = append(instances, upload.SourceInstance)
	}
	require.ElementsMatch(t, []string{"dt-v4", "dt-v5"}, instances)
}

type sourceStub struct {
	identity sources.Identity
}

func (s *sourceStub) Name() string                                 { return s.identity.Type }
func (s *sourceStub) Identity() sources.Identity                   { return s.identity }
func (s *sourceStub) Delete(context.Context, string, string) error { return nil }
func (s *sourceStub) GetVulnerabilities(context.Context, string, string, bool) ([]*sources.Vulnerability, error) {
	return nil, nil
}
func (s *sourceStub) GetVulnerabilitySummary(context.Context, string, string) (*sources.VulnerabilitySummary, error) {
	return nil, nil
}
func (s *sourceStub) IsTaskInProgress(context.Context, string) (bool, error) { return false, nil }
func (s *sourceStub) MaintainSuppressedVulnerabilities(context.Context, []*sources.SuppressedVulnerability) error {
	return nil
}
func (s *sourceStub) ProjectExists(context.Context, string, string) (bool, error) {
	return false, nil
}
func (s *sourceStub) UploadAttestation(context.Context, string, string, []byte) (*sources.UploadAttestationResponse, error) {
	return nil, nil
}

func TestImageReference(t *testing.T) {
	tests := []struct {
		name     string
		image    string
		tag      string
		expected string
	}{
		{
			name:     "regular tag",
			image:    "example.com/team/app",
			tag:      "1.2.3",
			expected: "example.com/team/app:1.2.3",
		},
		{
			name:     "digest tag",
			image:    "example.com/team/app",
			tag:      "sha256:abc",
			expected: "example.com/team/app@sha256:abc",
		},
		{
			name:     "digest tag with leading at",
			image:    "example.com/team/app",
			tag:      "@sha256:abc",
			expected: "example.com/team/app@sha256:abc",
		},
		{
			name:     "non sha256 digest tag",
			image:    "example.com/team/app",
			tag:      "sha512:abc",
			expected: "example.com/team/app@sha512:abc",
		},
		{
			name:     "non sha256 digest tag with leading at",
			image:    "example.com/team/app",
			tag:      "@sha512:abc",
			expected: "example.com/team/app@sha512:abc",
		},
		{
			name:     "tag and digest",
			image:    "example.com/team/app",
			tag:      "1.2.3@sha256:abc",
			expected: "example.com/team/app:1.2.3@sha256:abc",
		},
		{
			name:     "empty tag",
			image:    "example.com/team/app",
			tag:      "",
			expected: "example.com/team/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, imageReference(tt.image, tt.tag))
		})
	}
}
