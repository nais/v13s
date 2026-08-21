package manager

import (
	"context"
	"reflect"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
	"github.com/riverqueue/river"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeJobClient struct {
	addedJobs  []river.JobArgs
	startCalls int
	stopCalls  int
	workers    *river.Workers
}

func (f *fakeJobClient) AddJob(_ context.Context, args river.JobArgs) error {
	f.addedJobs = append(f.addedJobs, args)
	return nil
}

func (f *fakeJobClient) GetWorkers() *river.Workers { return f.workers }

func (f *fakeJobClient) Start(_ context.Context) error {
	f.startCalls++
	return nil
}

func (f *fakeJobClient) Stop(_ context.Context) error {
	f.stopCalls++
	return nil
}

func newWorkloadManagerForTest(q sql.Querier, jc *fakeJobClient, reconcileDeletionEnabled bool) *WorkloadManager {
	return &WorkloadManager{
		db:                       q,
		jobClient:                jc,
		reconcileDeletionEnabled: reconcileDeletionEnabled,
		log:                      logrus.NewEntry(logrus.New()),
	}
}

func registeredWorkerCount(t *testing.T, workers *river.Workers) int {
	t.Helper()

	value := reflect.ValueOf(workers).Elem().FieldByName("workersMap")
	require.True(t, value.IsValid())
	return value.Len()
}

func TestWorkloadManager_AddWorkload_EnqueuesAddWorkloadJob(t *testing.T) {
	jc := &fakeJobClient{}
	mgr := newWorkloadManagerForTest(nil, jc, true)
	workload := &model.Workload{Name: "app", Cluster: "dev", Namespace: "team", Type: model.WorkloadTypeApp}

	err := mgr.AddWorkload(context.Background(), workload)
	require.NoError(t, err)
	require.Len(t, jc.addedJobs, 1)

	job, ok := jc.addedJobs[0].(*AddWorkloadJob)
	require.True(t, ok)
	require.Same(t, workload, job.Workload)
}

func TestWorkloadManager_DeleteWorkload_EnqueuesDeleteWorkloadJob(t *testing.T) {
	jc := &fakeJobClient{}
	mgr := newWorkloadManagerForTest(nil, jc, true)
	workload := &model.Workload{Name: "app", Cluster: "dev", Namespace: "team", Type: model.WorkloadTypeApp}

	err := mgr.DeleteWorkload(context.Background(), workload)
	require.NoError(t, err)
	require.Len(t, jc.addedJobs, 1)

	job, ok := jc.addedJobs[0].(*DeleteWorkloadJob)
	require.True(t, ok)
	require.Same(t, workload, job.Workload)
}

func TestWorkloadManager_ReconcileWorkloads_EnqueuesDeleteJobsForOrphans(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)
	jc := &fakeJobClient{}

	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "replicator", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ImageTag: "old-tag"},
		{Name: "replicator-controller-manager-replicator", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ImageTag: "new-tag"},
	}, nil)

	mgr := newWorkloadManagerForTest(q, jc, true)
	mgr.ReconcileWorkloads(ctx, map[string][]*model.Workload{
		"dev": {
			{Name: "replicator-controller-manager-replicator", Namespace: "nais-system", Cluster: "dev", Type: model.WorkloadTypeDeployment},
		},
	})

	require.Len(t, jc.addedJobs, 1)
	job, ok := jc.addedJobs[0].(*DeleteWorkloadJob)
	require.True(t, ok)
	require.Equal(t, "replicator", job.Workload.Name)
	require.Equal(t, "nais-system", job.Workload.Namespace)
}

func TestNewContextStoresOneWorkloadManager(t *testing.T) {
	jc := &fakeJobClient{}
	mgr := &WorkloadManager{jobClient: jc}

	ctx := NewContext(context.Background(), mgr)

	require.Same(t, mgr, FromContext(ctx))
	require.Same(t, jc, JobClient(ctx))
}

func TestWorkloadManager_StartRegistersWorkersBeforeStartingClient(t *testing.T) {
	ctx := t.Context()

	workers := river.NewWorkers()
	jc := &fakeJobClient{workers: workers}
	mgr := &WorkloadManager{
		db:               nil,
		jobClient:        jc,
		log:              logrus.NewEntry(logrus.New()),
		addDispatcher:    NewDispatcher(func(context.Context, *model.Workload) error { return nil }, make(chan *model.Workload, 1), 1),
		deleteDispatcher: NewDispatcher(func(context.Context, *model.Workload) error { return nil }, make(chan *model.Workload, 1), 1),
	}

	require.NoError(t, mgr.Start(ctx))
	require.Error(t, mgr.Start(ctx))
	require.NoError(t, mgr.Stop(ctx))

	require.Equal(t, 1, jc.startCalls)
	require.Equal(t, 1, jc.stopCalls)
	require.Greater(t, registeredWorkerCount(t, workers), 0)
}
