package manager

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
)

type trackingJobClient struct {
	addedJobs []river.JobArgs
}

func (t *trackingJobClient) AddJob(_ context.Context, args river.JobArgs) error {
	t.addedJobs = append(t.addedJobs, args)
	return nil
}

func (t *trackingJobClient) GetWorkers() *river.Workers    { return nil }
func (t *trackingJobClient) Start(_ context.Context) error { return nil }
func (t *trackingJobClient) Stop(_ context.Context) error  { return nil }

var workloadID = pgtype.UUID{Bytes: [16]byte{1}, Valid: true}

func makeAddWorkloadJob(imageName, imageTag string) *river.Job[AddWorkloadJob] {
	return &river.Job[AddWorkloadJob]{
		Args: AddWorkloadJob{
			Workload: &model.Workload{
				Name:      "test-workload",
				Cluster:   "dev",
				Namespace: "test-ns",
				Type:      model.WorkloadTypeApp,
				ImageName: imageName,
				ImageTag:  imageTag,
			},
		},
	}
}

func TestAddWorkloadWorker_SkipsGetAttestationWhenImageUpdated(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	jc := &trackingJobClient{}

	db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
	db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(workloadID, nil)
	db.EXPECT().GetImage(mock.Anything, mock.Anything).Return(&sql.Image{
		Name:  "myimage",
		Tag:   "v1",
		State: sql.ImageStateUpdated,
	}, nil)
	db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
		return p.State == sql.WorkloadStateUpdated && p.ID == workloadID
	})).Return(nil)

	worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.NewEntry(logrus.New())}
	err := worker.Work(context.Background(), makeAddWorkloadJob("myimage", "v1"))

	require.NoError(t, err)
	require.Empty(t, jc.addedJobs, "GetAttestationJob should not be enqueued when image is already updated")
}

func TestAddWorkloadWorker_SkipsGetAttestationWhenImageFailed(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	jc := &trackingJobClient{}

	db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
	db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(workloadID, nil)
	db.EXPECT().GetImage(mock.Anything, mock.Anything).Return(&sql.Image{
		Name:  "myimage",
		Tag:   "v1",
		State: sql.ImageStateFailed,
	}, nil)
	db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
		return p.State == sql.WorkloadStateNoAttestation && p.ID == workloadID
	})).Return(nil)

	worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.NewEntry(logrus.New())}
	err := worker.Work(context.Background(), makeAddWorkloadJob("myimage", "v1"))

	require.NoError(t, err)
	require.Empty(t, jc.addedJobs, "GetAttestationJob should not be enqueued when image is already failed")
}

func TestAddWorkloadWorker_EnqueuesGetAttestationWhenImageInitialized(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	jc := &trackingJobClient{}

	db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
	db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(workloadID, nil)
	db.EXPECT().GetImage(mock.Anything, mock.Anything).Return(&sql.Image{
		Name:  "myimage",
		Tag:   "v1",
		State: sql.ImageStateInitialized,
	}, nil)
	db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
		return p.State == sql.WorkloadStateUpdated && p.ID == workloadID
	})).Return(nil)

	worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.NewEntry(logrus.New())}
	err := worker.Work(context.Background(), makeAddWorkloadJob("myimage", "v1"))

	require.NoError(t, err)
	require.Len(t, jc.addedJobs, 1, "GetAttestationJob should be enqueued when image is not yet processed")
	_, ok := jc.addedJobs[0].(*GetAttestationJob)
	require.True(t, ok, "enqueued job should be a GetAttestationJob")
}

func TestAddWorkloadWorker_FallsBackToGetAttestationOnGetImageError(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	jc := &trackingJobClient{}

	db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
	db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(workloadID, nil)
	db.EXPECT().GetImage(mock.Anything, mock.Anything).Return(nil, fmt.Errorf("db error"))
	db.EXPECT().UpdateWorkloadState(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateParams) bool {
		return p.State == sql.WorkloadStateUpdated && p.ID == workloadID
	})).Return(nil)

	worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.NewEntry(logrus.New())}
	err := worker.Work(context.Background(), makeAddWorkloadJob("myimage", "v1"))

	require.NoError(t, err)
	require.Len(t, jc.addedJobs, 1, "GetAttestationJob should be enqueued when GetImage fails")
}
