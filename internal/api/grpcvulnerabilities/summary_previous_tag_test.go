//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_SummariesUsePreviousTagWhileProcessing(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const namespace = "previous-tag"
	image := func(name, tag, state string, critical int32, age time.Duration) {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: name, Tag: tag, Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = $3 WHERE name = $1 AND tag = $2`, name, tag, state)
		require.NoError(t, err)
		if critical > 0 {
			_, err = db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{ImageName: name, ImageTag: tag, Critical: critical})
			require.NoError(t, err)
			_, err = pool.Exec(ctx, `UPDATE vulnerability_summary SET updated_at = NOW() - $3::INTERVAL WHERE image_name = $1 AND image_tag = $2`, name, tag, age.String())
			require.NoError(t, err)
		}
	}
	workload := func(name, imageName, tag string) {
		_, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: name, WorkloadType: "app", Namespace: namespace, Cluster: "cluster-1", ImageName: imageName, ImageTag: tag,
		})
		require.NoError(t, err)
	}

	image("fallback-image", "v0", "updated", 1, 48*time.Hour)
	image("fallback-image", "v1", "updated", 2, 24*time.Hour)
	image("fallback-image", "v2", "initialized", 0, 0)
	workload("w-fallback", "fallback-image", "v2")

	image("resync-image", "v0", "updated", 9, 48*time.Hour)
	image("resync-image", "v1", "resync", 3, time.Hour)
	workload("w-resync", "resync-image", "v1")

	image("failed-image", "v0", "updated", 4, 24*time.Hour)
	image("failed-image", "v1", "failed", 0, 0)
	workload("w-failed", "failed-image", "v1")

	image("ready-image", "v1", "updated", 5, time.Hour)
	workload("w-ready", "ready-image", "v1")

	t.Run("team summary counts processing workloads with data as covered", func(t *testing.T) {
		resp, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter(namespace))
		require.NoError(t, err)
		assert.Equal(t, int32(2+3+5), resp.GetVulnerabilitySummary().GetCritical())
		assert.Equal(t, int32(4), resp.GetWorkloadCount())
		assert.Equal(t, int32(3), resp.GetSbomCount())

		batch, err := client.GetVulnerabilitySummaries(ctx, []string{namespace})
		require.NoError(t, err)
		assert.Equal(t, int32(2+3+5), batch.GetSummaries()[namespace].GetVulnerabilitySummary().GetCritical())
		assert.Equal(t, int32(3), batch.GetSummaries()[namespace].GetSbomCount())
	})

	t.Run("workload list shows previous tag data while processing", func(t *testing.T) {
		resp, err := client.ListVulnerabilitySummaries(ctx, vulnerabilities.NamespaceFilter(namespace), vulnerabilities.Limit(10))
		require.NoError(t, err)
		type got struct {
			status   vulnerabilities.SbomStatus
			tag      string
			critical int32
			stale    string
			counts   bool
		}
		byName := map[string]got{}
		for _, n := range resp.GetNodes() {
			byName[n.GetWorkload().GetName()] = got{
				status:   n.GetSbomStatus().GetStatus(),
				tag:      n.GetWorkload().GetImageTag(),
				critical: n.GetVulnerabilitySummary().GetCritical(),
				stale:    n.GetVulnerabilitySummary().GetStaleImageTag(),
				counts:   n.GetVulnerabilitySummary() != nil,
			}
		}
		assert.Equal(t, map[string]got{
			"w-fallback": {vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, "v2", 2, "v1", true},
			"w-resync":   {vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, "v1", 3, "", true},
			"w-failed":   {vulnerabilities.SbomStatus_SBOM_STATUS_FAILED, "v1", 0, "", false},
			"w-ready":    {vulnerabilities.SbomStatus_SBOM_STATUS_READY, "v1", 5, "", true},
		}, byName)
	})

	t.Run("metrics use previous tag data while processing", func(t *testing.T) {
		rows, err := db.ListVulnerabilitySummariesForMetrics(ctx, nil)
		require.NoError(t, err)
		critical := map[string]int32{}
		for _, r := range rows {
			if r.Namespace == namespace {
				critical[r.WorkloadName] = r.Critical
			}
		}
		assert.Equal(t, map[string]int32{"w-fallback": 2, "w-resync": 3, "w-failed": 0, "w-ready": 5}, critical)
	})
}
