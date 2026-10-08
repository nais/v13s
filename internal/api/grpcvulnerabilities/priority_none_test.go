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

func TestServer_ListVulnerabilitySummaries_PriorityNone(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const namespace = "priority-none"
	workload := func(name, imageState string, summaryTier *int32, workloadState sql.WorkloadState) {
		image := "img-" + name
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image, Tag: "v1", Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = $2 WHERE name = $1`, image, imageState)
		require.NoError(t, err)
		if summaryTier != nil {
			_, err = db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{ImageName: image, ImageTag: "v1"})
			require.NoError(t, err)
			if *summaryTier > 0 {
				_, err = pool.Exec(ctx, `UPDATE vulnerability_summary SET monitor = 1, top_risk_tier = $2 WHERE image_name = $1`, image, *summaryTier)
				require.NoError(t, err)
			}
		}
		_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: name, WorkloadType: "app", Namespace: namespace, Cluster: "cluster-1", ImageName: image, ImageTag: "v1",
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			State: workloadState,
			ID:    getWorkloadID(ctx, t, db, name, image, "v1"),
		}))
	}
	noFindings, monitor := int32(0), int32(4)
	workload("clean", "updated", &noFindings, sql.WorkloadStateUpdated)
	workload("clean-resyncing", "resync", &noFindings, sql.WorkloadStateUpdated)
	workload("with-findings", "updated", &monitor, sql.WorkloadStateUpdated)
	workload("without-summary", "updated", nil, sql.WorkloadStateUpdated)
	workload("failed", "updated", &noFindings, sql.WorkloadStateFailed)
	workload("no-attestation", "updated", &noFindings, sql.WorkloadStateNoAttestation)

	names := func(priorities ...vulnerabilities.Priority) []string {
		resp, err := client.ListVulnerabilitySummaries(ctx, vulnerabilities.NamespaceFilter(namespace), vulnerabilities.PriorityFilter(priorities...), vulnerabilities.Limit(20))
		require.NoError(t, err)
		out := []string{}
		for _, n := range resp.GetNodes() {
			out = append(out, n.GetWorkload().GetName())
		}
		slices.Sort(out)
		return out
	}

	assert.Equal(t, []string{"clean", "clean-resyncing"}, names(vulnerabilities.Priority_PRIORITY_NONE))
	assert.Equal(t, []string{"with-findings"}, names(vulnerabilities.Priority_PRIORITY_MONITOR))
	assert.Equal(t, []string{"clean", "clean-resyncing", "with-findings"}, names(vulnerabilities.Priority_PRIORITY_MONITOR, vulnerabilities.Priority_PRIORITY_NONE))
}
