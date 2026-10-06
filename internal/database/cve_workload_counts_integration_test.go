//go:build integration_test

package database_test

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestRefreshCveWorkloadCountsSkipsWhileAnotherPodHoldsLock(t *testing.T) {
	const refreshLockKey = int64(7705370003)

	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	refresher := database.NewCveWorkloadCountsRefresher(pool, logrus.NewEntry(logrus.StandardLogger()))

	_, err := pool.Exec(ctx, "INSERT INTO images (name, tag) VALUES ('image', 'v1')")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag) VALUES ('workload', 'app', 'namespace', 'cluster', 'image', 'v1')")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs) VALUES ('CVE-TEST', 'test', 'test', 'test', 1, '{}')")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version) VALUES ('image', 'v1', 'package', 'CVE-TEST', 'test', '')")
	require.NoError(t, err)

	otherPod, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer otherPod.Release()
	otherQuerier := sql.New(otherPod)
	locked, err := otherQuerier.TryAdvisoryLock(ctx, refreshLockKey)
	require.NoError(t, err)
	require.True(t, locked)

	require.NoError(t, refresher.Refresh(ctx))
	var count int
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM mv_cve_workload_counts").Scan(&count))
	require.Zero(t, count)

	released, err := otherQuerier.AdvisoryUnlock(ctx, refreshLockKey)
	require.NoError(t, err)
	require.True(t, released)

	require.NoError(t, refresher.Refresh(ctx))
	require.NoError(t, pool.QueryRow(ctx, "SELECT COUNT(*) FROM mv_cve_workload_counts").Scan(&count))
	require.Equal(t, 1, count)
}
