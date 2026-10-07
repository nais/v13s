//go:build integration_test

package grpcvulnerabilities_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_MeanTimeToFix(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: "mttf-image", Tag: "v1", Metadata: map[string]string{}}))
	upsertWorkload := func(name, namespace, workloadType string) pgtype.UUID {
		id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: name, WorkloadType: workloadType, Namespace: namespace, Cluster: "cluster-1", ImageName: "mttf-image", ImageTag: "v1",
		})
		require.NoError(t, err)
		return id
	}
	app := upsertWorkload("mttf-app", "mttf", "app")
	job := upsertWorkload("mttf-job", "mttf-other", "job")

	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := func(offset int) time.Time { return today.AddDate(0, 0, offset) }
	snapshot := func(workloadID any, name, namespace, workloadType string, offset, critical, high int) {
		_, err := pool.Exec(ctx, `
			INSERT INTO vuln_daily_by_workload (
				snapshot_date, workload_id, workload_name, cluster, namespace, workload_type,
				critical, high, medium, low, unassigned, total, risk_score
			) VALUES ($1, $2, $3, 'cluster-1', $4, $5, $6::INT, $7::INT, 0, 0, 0, $6::INT + $7::INT, 0)
		`, day(offset), workloadID, name, namespace, workloadType, critical, high)
		require.NoError(t, err)
	}
	snapshot(app, "mttf-app", "mttf", "app", -10, 1, 0)
	snapshot(app, "mttf-app", "mttf", "app", -8, 1, 2)
	snapshot(app, "mttf-app", "mttf", "app", -6, 0, 2)
	snapshot(app, "mttf-app", "mttf", "app", -4, 0, 0)
	snapshot(app, "mttf-app", "mttf", "app", -2, 3, 0)
	snapshot(job, "mttf-job", "mttf-other", "job", -8, 2, 0)
	snapshot(job, "mttf-job", "mttf-other", "job", -6, 0, 0)

	countLifetimes := func() int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM vuln_fix_lifetime`).Scan(&n))
		return n
	}
	require.NoError(t, db.UpsertVulnerabilityLifetimes(ctx))
	require.NoError(t, db.UpsertVulnerabilityLifetimes(ctx))
	require.Equal(t, 4, countLifetimes(), "each lifetime is stored once")

	trend := func(opts ...vulnerabilities.Option) []string {
		resp, err := client.ListMeanTimeToFixTrendBySeverity(ctx, opts...)
		require.NoError(t, err)
		out := make([]string, 0, len(resp.Points))
		for _, p := range resp.Points {
			out = append(out, fmt.Sprintf("%s sev=%d mean=%d count=%d workloads=%d",
				p.SnapshotDate.AsTime().Format(time.DateOnly), p.Severity, p.MeanTimeToFixDays, p.FixedCount, p.WorkloadCount))
		}
		return out
	}
	date := func(offset int) string { return day(offset).Format(time.DateOnly) }

	points := func(from, severity, mean, count, workloads int) []string {
		out := []string{}
		for offset := from; offset <= 0; offset++ {
			out = append(out, fmt.Sprintf("%s sev=%d mean=%d count=%d workloads=%d", date(offset), severity, mean, count, workloads))
		}
		return out
	}
	sorted := func(lists ...[]string) []string {
		out := []string{}
		for _, l := range lists {
			out = append(out, l...)
		}
		slices.Sort(out)
		return out
	}

	t.Run("trend is the running mean of all fixes up to each day", func(t *testing.T) {
		assert.Equal(t, sorted(points(-6, 0, 3, 2, 2), points(-4, 1, 4, 1, 1)), trend())
	})

	t.Run("trend filters", func(t *testing.T) {
		assert.Equal(t, sorted(points(-6, 0, 4, 1, 1), points(-4, 1, 4, 1, 1)), trend(vulnerabilities.NamespaceFilter("mttf")))
		assert.Equal(t, points(-6, 0, 2, 1, 1), trend(vulnerabilities.WorkloadTypeFilter("job")))
		assert.Equal(t, points(-6, 0, 2, 1, 1), trend(vulnerabilities.WorkloadFilter("mttf-job")))
		assert.Empty(t, trend(vulnerabilities.ClusterFilter("cluster-2")))
	})

	t.Run("since limits the days but keeps earlier fixes in the mean", func(t *testing.T) {
		assert.Equal(t, sorted(points(-5, 0, 3, 2, 2), points(-4, 1, 4, 1, 1)), trend(vulnerabilities.Since(day(-5))))
	})

	t.Run("since with fixed type only counts fixes from that day", func(t *testing.T) {
		assert.Equal(t, points(-4, 1, 4, 1, 1), trend(vulnerabilities.Since(day(-5)), vulnerabilities.SinceTypeFilter(vulnerabilities.SinceType_FIXED)))
	})

	t.Run("an open lifetime is updated when it is fixed", func(t *testing.T) {
		snapshot(app, "mttf-app", "mttf", "app", -1, 0, 0)
		require.NoError(t, db.UpsertVulnerabilityLifetimes(ctx))
		assert.Equal(t, 4, countLifetimes())
		assert.Equal(t, sorted(points(-6, 0, 3, 2, 2)[:5], points(-1, 0, 2, 3, 2), points(-4, 1, 4, 1, 1)), trend())
	})

	t.Run("trend matches the per-day snapshots it replaces", func(t *testing.T) {
		rows, err := pool.Query(ctx, `
			SELECT
				d::DATE, u.severity, AVG(u.fix_duration)::INT, COUNT(*), COUNT(DISTINCT u.workload_id)
			FROM generate_series($1::DATE, CURRENT_DATE, INTERVAL '1 day') d
			CROSS JOIN LATERAL vuln_upsert_data_for_date(d::DATE) u
			WHERE u.is_fixed AND u.workload_id IN (SELECT id FROM workloads)
			GROUP BY d, u.severity
			ORDER BY d, u.severity
		`, day(-10))
		require.NoError(t, err)
		defer rows.Close()
		want := []string{}
		for rows.Next() {
			var d time.Time
			var severity, mean, count, workloads int
			require.NoError(t, rows.Scan(&d, &severity, &mean, &count, &workloads))
			want = append(want, fmt.Sprintf("%s sev=%d mean=%d count=%d workloads=%d", d.Format(time.DateOnly), severity, mean, count, workloads))
		}
		require.NoError(t, rows.Err())
		assert.Equal(t, want, trend())
	})

	t.Run("snapshots for unknown workloads are skipped", func(t *testing.T) {
		snapshot(uuid.New(), "orphan", "mttf", "app", -3, 1, 0)
		require.NoError(t, db.UpsertVulnerabilityLifetimes(ctx))
		assert.Equal(t, 4, countLifetimes())
	})
}
