package manager

import (
	"context"
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

type countingJobClient struct {
	count int
}

func (c *countingJobClient) AddJob(_ context.Context, _ river.JobArgs) error {
	c.count++
	return nil
}
func (c *countingJobClient) GetWorkers() *river.Workers    { return nil }
func (c *countingJobClient) Start(_ context.Context) error { return nil }
func (c *countingJobClient) Stop(_ context.Context) error  { return nil }

func newTestWorkloadManager(t *testing.T, q *sqmock.MockQuerier) *WorkloadManager {
	t.Helper()
	return &WorkloadManager{
		db:              q,
		jobClient:       &stubJobClient{},
		reconcileWorkloadsEnabled: true,
		log:             logrus.NewEntry(logrus.New()),
	}
}

func newDryRunWorkloadManager(t *testing.T, q *sqmock.MockQuerier) *WorkloadManager {
	t.Helper()
	return &WorkloadManager{
		db:                        q,
		jobClient:                 &stubJobClient{},
		reconcileWorkloadsEnabled: false,
		log:                       logrus.NewEntry(logrus.New()),
	}
}

func TestReconcileWorkloads_DeletesOrphan(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	// DB has two workloads in dev cluster
	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "replicator", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ImageTag: "old-tag", ID: pgtype.UUID{}},
		{Name: "replicator-controller-manager-replicator", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ImageTag: "new-tag", ID: pgtype.UUID{}},
	}, nil)

	// Only the new one is alive in k8s
	live := map[string][]*model.Workload{
		"dev": {
			{Name: "replicator-controller-manager-replicator", Namespace: "nais-system", Cluster: "dev", Type: "deployment"},
		},
	}

	counter := &countingJobClient{}
	mgr := newTestWorkloadManager(t, q)
	mgr.jobClient = counter
	mgr.ReconcileWorkloads(ctx, live)

	require.Equal(t, 1, counter.count, "should enqueue one delete job for the orphan workload")
}

func TestReconcileWorkloads_KeepsLiveWorkloads(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "myapp", Namespace: "default", Cluster: "dev", WorkloadType: "app", ImageTag: "tag1", ID: pgtype.UUID{}},
	}, nil)

	live := map[string][]*model.Workload{
		"dev": {
			{Name: "myapp", Namespace: "default", Cluster: "dev", Type: "app"},
		},
	}

	mgr := newTestWorkloadManager(t, q)
	mgr.ReconcileWorkloads(ctx, live) // should not enqueue any deletes
}

func TestReconcileWorkloads_SkipsUnmanagedClusters(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	// prod is NOT in liveByCluster (e.g. informer had no active informers for it)
	// — should not query DB for prod at all
	live := map[string][]*model.Workload{
		"dev": {},
	}
	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{}, nil)

	mgr := newTestWorkloadManager(t, q)
	mgr.ReconcileWorkloads(ctx, live)

	q.AssertNotCalled(t, "ListWorkloadsByCluster", mock.Anything, "prod")
}

func TestReconcileWorkloads_DryRun_DoesNotDelete(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "zombie", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ID: pgtype.UUID{}},
	}, nil)

	live := map[string][]*model.Workload{
		"dev": {}, // zombie not present in k8s
	}

	counter := &countingJobClient{}
	mgr := newDryRunWorkloadManager(t, q)
	mgr.jobClient = counter
	mgr.ReconcileWorkloads(ctx, live)

	require.Zero(t, counter.count, "dry-run should not enqueue any delete jobs")
}

func TestReconcileWorkloads_LiveRun_Deletes(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "zombie", Namespace: "nais-system", Cluster: "dev", WorkloadType: "deployment", ID: pgtype.UUID{}},
	}, nil)

	live := map[string][]*model.Workload{
		"dev": {},
	}

	counter := &countingJobClient{}
	mgr := newTestWorkloadManager(t, q) // reconcileEnabled=true
	mgr.jobClient = counter
	mgr.ReconcileWorkloads(ctx, live)

	require.Equal(t, 1, counter.count, "live-run should enqueue exactly one delete job")
}

func TestReconcileWorkloads_EmptyCluster_DeletesAll(t *testing.T) {
	ctx := context.Background()
	q := sqmock.NewMockQuerier(t)

	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{
		{Name: "stale", Namespace: "default", Cluster: "dev", WorkloadType: "deployment", ID: pgtype.UUID{}},
	}, nil)

	// Cluster managed but k8s has no workloads at all
	live := map[string][]*model.Workload{
		"dev": {},
	}

	counter := &countingJobClient{}
	mgr := newTestWorkloadManager(t, q)
	mgr.jobClient = counter
	mgr.ReconcileWorkloads(ctx, live)

	require.Equal(t, 1, counter.count, "should enqueue one delete job when cluster has no live workloads")
}
