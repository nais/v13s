package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
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

type fixedJobTime struct{ now time.Time }

func (f fixedJobTime) Now() time.Time       { return f.now }
func (f fixedJobTime) NowOrNil() *time.Time { return &f.now }

type inMemoryUniqueInsert struct {
	river.MiddlewareDefaults
	seen   map[string]*rivertype.JobRow
	work   func(context.Context, *river.Job[AddWorkloadJob]) error
	nextID int64
}

func (m *inMemoryUniqueInsert) InsertMany(ctx context.Context, params []*rivertype.JobInsertParams, _ func(context.Context) ([]*rivertype.JobInsertResult, error)) ([]*rivertype.JobInsertResult, error) {
	results := make([]*rivertype.JobInsertResult, 0, len(params))
	for _, param := range params {
		key := string(param.UniqueKey)
		if previous, exists := m.seen[key]; key != "" && exists {
			results = append(results, &rivertype.JobInsertResult{Job: previous, UniqueSkippedAsDuplicate: true})
			continue
		}
		var args AddWorkloadJob
		if err := json.Unmarshal(param.EncodedArgs, &args); err != nil {
			return nil, err
		}
		if err := m.work(ctx, &river.Job[AddWorkloadJob]{Args: args}); err != nil {
			return nil, err
		}
		m.nextID++
		row := &rivertype.JobRow{ID: m.nextID, State: rivertype.JobStateCompleted}
		if key != "" {
			m.seen[key] = row
		}
		results = append(results, &rivertype.JobInsertResult{Job: row})
	}
	return results, nil
}

type insertingJobClient struct {
	trackingJobClient
	client *river.Client[pgx.Tx]
}

func (c *insertingJobClient) AddJob(ctx context.Context, args river.JobArgs) error {
	_, err := c.client.InsertTx(ctx, nil, args, nil)
	return err
}

func TestAddWorkloadWorker_LabelRevertWithinUniquePeriod(t *testing.T) {
	ctx := context.Background()
	db := sqmock.NewMockQuerier(t)
	currentLabels := typeext.MapStringString{}
	db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
	db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(pgtype.UUID{}, nil)
	db.On("UpdateWorkloadLabels", mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		currentLabels = args.Get(1).(sql.UpdateWorkloadLabelsParams).Labels
	})
	worker := &AddWorkloadWorker{db: db, jobClient: &trackingJobClient{}, log: logrus.New()}
	insert := &inMemoryUniqueInsert{seen: make(map[string]*rivertype.JobRow), work: worker.Work}
	client, err := river.NewClient(riverpgxv5.New(nil), &river.Config{
		Middleware: []rivertype.Middleware{insert},
		Test:       river.TestConfig{Time: fixedJobTime{now: time.Date(2026, 1, 1, 0, 0, 5, 0, time.UTC)}},
	})
	require.NoError(t, err)
	mgr := &WorkloadManager{jobClient: &insertingJobClient{client: client}, log: logrus.New()}
	for index, labels := range []map[string]string{{}, {"owner": "x"}, {}} {
		workload := makeAddWorkloadJob("image", "v1").Args.Workload
		workload.Labels = labels
		workload.ResourceVersion = fmt.Sprint(index + 1)
		require.NoError(t, mgr.AddWorkload(ctx, workload))
		require.Equal(t, typeext.MapStringString(labels), currentLabels, "each label change must reach persistence")
	}
	workload := makeAddWorkloadJob("image", "v1").Args.Workload
	require.NoError(t, mgr.AddWorkload(ctx, workload))
	require.NoError(t, mgr.AddWorkload(ctx, workload))
	require.Equal(t, int64(4), insert.nextID, "metadata-free jobs must retain deduplication")
}

type labelOnlyUpdateCase struct {
	name   string
	labels map[string]string
	want   typeext.MapStringString
	err    error
}

func TestAddWorkloadWorker_LabelOnlyUpdate(t *testing.T) {
	for _, tt := range []labelOnlyUpdateCase{
		{"changed", map[string]string{"owner": "new", "app": "hidden"}, typeext.MapStringString{"owner": "new"}, nil},
		{"removed", map[string]string{}, typeext.MapStringString{}, nil},
		{"database failure", map[string]string{}, typeext.MapStringString{}, errors.New("write failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := sqmock.NewMockQuerier(t)
			jc := &trackingJobClient{}
			db.EXPECT().CreateImage(mock.Anything, mock.Anything).Return(nil)
			db.EXPECT().InitializeWorkload(mock.Anything, mock.Anything).Return(pgtype.UUID{}, nil)
			db.EXPECT().UpdateWorkloadLabels(mock.Anything, sql.UpdateWorkloadLabelsParams{
				Name: "test-workload", Cluster: "dev", Namespace: "test-ns", WorkloadType: "app",
				ImageName: "image", ImageTag: "v1", Labels: tt.want,
			}).Return(tt.err).Once()
			job := makeAddWorkloadJob("image", "v1")
			job.Args.Workload.Labels = tt.labels
			worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.New()}
			err := worker.Work(context.Background(), job)
			require.ErrorIs(t, err, tt.err)
			require.Empty(t, jc.addedJobs)
		})
	}
}

func makeAddWorkloadJob(imageName, imageTag string) *river.Job[AddWorkloadJob] {
	return &river.Job[AddWorkloadJob]{
		Args: AddWorkloadJob{
			Workload: &model.Workload{
				Name:            "test-workload",
				Cluster:         "dev",
				Namespace:       "test-ns",
				Type:            model.WorkloadTypeApp,
				ImageName:       imageName,
				ImageTag:        imageTag,
				ResourceVersion: "1",
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

func TestAddWorkloadWorker_EnqueuesGetAttestationWhenImageFailed(t *testing.T) {
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
		return p.State == sql.WorkloadStateUpdated && p.ID == workloadID
	})).Return(nil)

	worker := &AddWorkloadWorker{db: db, jobClient: jc, log: logrus.NewEntry(logrus.New())}
	err := worker.Work(context.Background(), makeAddWorkloadJob("myimage", "v1"))

	require.NoError(t, err)
	require.Len(t, jc.addedJobs, 1, "GetAttestationJob should be enqueued when image is failed — it sets the correct terminal state")
	_, ok := jc.addedJobs[0].(*GetAttestationJob)
	require.True(t, ok, "enqueued job should be a GetAttestationJob")
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
	_, ok := jc.addedJobs[0].(*GetAttestationJob)
	require.True(t, ok, "enqueued job should be a GetAttestationJob")
}
