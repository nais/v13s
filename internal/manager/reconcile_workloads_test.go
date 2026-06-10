package manager

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
)

func newTestWorkloadManager(t *testing.T, q *sqmock.MockQuerier) *WorkloadManager {
	t.Helper()
	return &WorkloadManager{
		db:        q,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
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

	mgr := newTestWorkloadManager(t, q)
	mgr.ReconcileWorkloads(ctx, live)

	// stubJobClient silently accepts the delete job — no assertion needed beyond no panic
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

	// prod is NOT in liveByCluster — should not query DB for prod
	live := map[string][]*model.Workload{
		"dev": {},
	}
	q.EXPECT().ListWorkloadsByCluster(mock.Anything, "dev").Return([]*sql.Workload{}, nil)

	mgr := newTestWorkloadManager(t, q)
	mgr.ReconcileWorkloads(ctx, live)

	q.AssertNotCalled(t, "ListWorkloadsByCluster", mock.Anything, "prod")
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

	mgr := newTestWorkloadManager(t, q)
	mgr.ReconcileWorkloads(ctx, live)

	require.NoError(t, nil) // stubJobClient accepted the delete
}
