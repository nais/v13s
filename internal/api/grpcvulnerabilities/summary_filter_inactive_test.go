//go:build integration_test

package grpcvulnerabilities_test

import (
	"slices"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_SummaryFiltersExcludeInactiveWorkloads(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const namespace = "summary-filter-inactive"
	workload := func(name string, workloadState sql.WorkloadState, imageState string) {
		image := "img-" + name
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image, Tag: "v1", Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = $2 WHERE name = $1`, image, imageState)
		require.NoError(t, err)
		_, err = db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{ImageName: image, ImageTag: "v1", Critical: 1})
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `UPDATE vulnerability_summary SET high_risk = 1, top_risk_tier = 2, kev_count = 1 WHERE image_name = $1`, image)
		require.NoError(t, err)
		_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: name, WorkloadType: "app", Namespace: namespace, Cluster: "cluster-1", ImageName: image, ImageTag: "v1",
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			State: workloadState,
			ID:    getWorkloadID(ctx, t, db, name, image, "v1"),
		}))
	}
	workload("active", sql.WorkloadStateUpdated, "updated")
	// Each inactive workload fails exactly one of the two guards.
	workload("wl-no-attestation", sql.WorkloadStateNoAttestation, "updated")
	workload("wl-failed", sql.WorkloadStateFailed, "updated")
	workload("wl-unrecoverable", sql.WorkloadStateUnrecoverable, "updated")
	workload("img-failed", sql.WorkloadStateUpdated, "failed")
	workload("img-unused", sql.WorkloadStateUpdated, "unused")

	names := func(t *testing.T, opts ...vulnerabilities.Option) []string {
		resp, err := client.ListVulnerabilitySummaries(ctx, append(opts, vulnerabilities.NamespaceFilter(namespace), vulnerabilities.Limit(10))...)
		require.NoError(t, err)
		out := []string{}
		for _, n := range resp.GetNodes() {
			out = append(out, n.GetWorkload().GetName())
		}
		slices.Sort(out)
		return out
	}

	t.Run("priority filter lists only active workloads", func(t *testing.T) {
		assert.Equal(t, []string{"active"}, names(t, vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH)))
	})

	t.Run("kev filter lists only active workloads", func(t *testing.T) {
		assert.Equal(t, []string{"active"}, names(t, vulnerabilities.KevFilter(true)))
	})

	t.Run("unfiltered list still includes inactive workloads", func(t *testing.T) {
		assert.Equal(t, []string{"active", "img-failed", "img-unused", "wl-failed", "wl-no-attestation", "wl-unrecoverable"}, names(t))
	})

	t.Run("team summary counts only active workloads when filtered", func(t *testing.T) {
		for _, opt := range []vulnerabilities.Option{
			vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH),
			vulnerabilities.KevFilter(true),
		} {
			resp, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter(namespace), opt)
			require.NoError(t, err)
			assert.Equal(t, int32(1), resp.GetWorkloadCount())

			batch, err := client.GetVulnerabilitySummaries(ctx, []string{namespace}, opt)
			require.NoError(t, err)
			assert.Equal(t, int32(1), batch.GetSummaries()[namespace].GetWorkloadCount())
		}
	})

	t.Run("team summary counts every workload when unfiltered", func(t *testing.T) {
		resp, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter(namespace))
		require.NoError(t, err)
		assert.Equal(t, int32(6), resp.GetWorkloadCount())
	})
}
