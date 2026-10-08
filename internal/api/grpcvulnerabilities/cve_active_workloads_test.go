//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_CveWorkloadsExcludeInactive(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const (
		namespace = "cve-inactive"
		cveID     = "CVE-INACTIVE-1"
	)
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{{CveID: cveID, Severity: int32(vulnerabilities.Severity_CRITICAL), Refs: map[string]string{}}}).
		Exec(func(i int, err error) { require.NoError(t, err) })

	workload := func(name, imageState string, workloadState sql.WorkloadState) {
		image := "img-" + name
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image, Tag: "v1", Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = $2 WHERE name = $1`, image, imageState)
		require.NoError(t, err)
		db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{{ImageName: image, ImageTag: "v1", Package: "pkg", CveID: cveID, Source: "test"}}).
			Exec(func(i int, err error) { require.NoError(t, err) })
		_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: name, WorkloadType: "app", Namespace: namespace, Cluster: "cluster-1", ImageName: image, ImageTag: "v1",
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			State: workloadState,
			ID:    getWorkloadID(ctx, t, db, name, image, "v1"),
		}))
	}
	workload("active", "updated", sql.WorkloadStateUpdated)
	workload("no-attestation", "updated", sql.WorkloadStateNoAttestation)
	workload("image-failed", "failed", sql.WorkloadStateUpdated)
	require.NoError(t, db.RefreshCveWorkloadCounts(ctx))

	t.Run("workloads for cve only lists active workloads", func(t *testing.T) {
		resp, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{cveID}}, vulnerabilities.Limit(10))
		require.NoError(t, err)
		require.Len(t, resp.GetNodes(), 1)
		assert.Equal(t, "active", resp.GetNodes()[0].GetWorkloadRef().GetName())
		assert.Equal(t, int64(1), resp.GetPageInfo().GetTotalCount())
	})

	affected := func(t *testing.T, opts ...vulnerabilities.Option) int32 {
		resp, err := client.ListCveSummaries(ctx, append(opts, vulnerabilities.NamespaceFilter(namespace), vulnerabilities.Limit(10))...)
		require.NoError(t, err)
		for _, n := range resp.GetNodes() {
			if n.GetCve().GetId() == cveID {
				return n.GetAffectedWorkloads()
			}
		}
		return 0
	}

	t.Run("cve summaries from counts only count active workloads", func(t *testing.T) {
		assert.Equal(t, int32(1), affected(t))
	})

	t.Run("cve summaries for a workload exclude inactive workloads", func(t *testing.T) {
		assert.Equal(t, int32(1), affected(t, vulnerabilities.WorkloadFilter("active")))
		assert.Equal(t, int32(0), affected(t, vulnerabilities.WorkloadFilter("no-attestation")))
		assert.Equal(t, int32(0), affected(t, vulnerabilities.WorkloadFilter("image-failed")))
	})
}
