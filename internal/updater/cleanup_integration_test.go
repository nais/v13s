//go:build integration_test

package updater_test

import (
	"context"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupUnusedImages(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: "CVE-CLEANUP-1", CveTitle: "title", CveDesc: "desc", CveLink: "link", Severity: 1, Refs: map[string]string{}},
	}).Exec(func(i int, err error) { require.NoError(t, err) })

	createImage := func(name, state string, unusedFor time.Duration, withWorkload bool) {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: name, Tag: "v1", Metadata: map[string]string{}}))
		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
			{ImageName: name, ImageTag: "v1", Package: "pkg", CveID: "CVE-CLEANUP-1", Source: "test"},
		}).Exec(func(i int, err error) { require.NoError(t, err) })
		require.NoError(t, db.UpdateImageSyncStatus(ctx, sql.UpdateImageSyncStatusParams{
			ImageName: name, ImageTag: "v1", StatusCode: "ok", Reason: "test", Source: "test",
		}))
		if withWorkload {
			_, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
				Name: name, WorkloadType: "app", Namespace: "team", Cluster: "cluster", ImageName: name, ImageTag: "v1",
			})
			require.NoError(t, err)
		}
		_, err := pool.Exec(ctx, `UPDATE images SET state = $2, updated_at = NOW() - $3::INTERVAL WHERE name = $1`,
			name, state, unusedFor.String())
		require.NoError(t, err)
	}
	createImage("old-unused-1", "unused", 90*24*time.Hour, false)
	createImage("old-unused-2", "unused", 61*24*time.Hour, false)
	createImage("recent-unused", "unused", 10*24*time.Hour, false)
	createImage("old-unused-with-workload", "unused", 90*24*time.Hour, true)
	createImage("old-updated", "updated", 90*24*time.Hour, false)

	runtimeCfg := updater.DefaultRuntimeConfig(updater.ScheduleConfig{Type: updater.SchedulerInterval, Interval: time.Minute})
	runtimeCfg.CleanupUnusedImages.BatchSize = 1
	u := updater.NewUpdaterWithRuntimeConfig(pool, nil, logrus.NewEntry(logrus.StandardLogger()), config.KevConfig{}, config.OsvConfig{}, runtimeCfg)
	require.NoError(t, u.CleanupUnusedImages(ctx))

	count := func(query string, name string) int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, query, name).Scan(&n))
		return n
	}
	for name, wantKept := range map[string]bool{
		"old-unused-1":             false,
		"old-unused-2":             false,
		"recent-unused":            true,
		"old-unused-with-workload": true,
		"old-updated":              true,
	} {
		want := 0
		if wantKept {
			want = 1
		}
		assert.Equal(t, want, count(`SELECT COUNT(*) FROM images WHERE name = $1`, name), name)
		assert.Equal(t, want, count(`SELECT COUNT(*) FROM vulnerabilities WHERE image_name = $1`, name), name)
		assert.Equal(t, want, count(`SELECT COUNT(*) FROM image_sync_status WHERE image_name = $1`, name), name)
	}
	assert.Equal(t, 1, count(`SELECT COUNT(*) FROM workloads WHERE image_name = $1`, "old-unused-with-workload"))

	t.Run("max per run limits the number of deleted images", func(t *testing.T) {
		for _, name := range []string{"capped-1", "capped-2", "capped-3"} {
			createImage(name, "unused", 90*24*time.Hour, false)
		}
		capped := runtimeCfg
		capped.CleanupUnusedImages.BatchSize = 2
		capped.CleanupUnusedImages.MaxPerRun = 2
		u := updater.NewUpdaterWithRuntimeConfig(pool, nil, logrus.NewEntry(logrus.StandardLogger()), config.KevConfig{}, config.OsvConfig{}, capped)
		require.NoError(t, u.CleanupUnusedImages(ctx))
		assert.Equal(t, 1, count(`SELECT COUNT(*) FROM images WHERE name LIKE $1`, "capped-%"))
		require.NoError(t, u.CleanupUnusedImages(ctx))
		assert.Equal(t, 0, count(`SELECT COUNT(*) FROM images WHERE name LIKE $1`, "capped-%"))
	})

	t.Run("a cleaned up image can be deployed again", func(t *testing.T) {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: "old-unused-1", Tag: "v1", Metadata: map[string]string{}}))
		_, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: "redeployed", WorkloadType: "app", Namespace: "team", Cluster: "cluster", ImageName: "old-unused-1", ImageTag: "v1",
		})
		require.NoError(t, err)
		assert.Equal(t, "initialized", func() string {
			var state string
			require.NoError(t, pool.QueryRow(ctx, `SELECT state FROM images WHERE name = $1`, "old-unused-1").Scan(&state))
			return state
		}())
	})
}
