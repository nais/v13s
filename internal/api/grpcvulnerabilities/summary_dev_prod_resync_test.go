//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_SummariesKeepDevAndProdSeparateDuringResync(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const imageName = "registry.example/amt/amt-pdfgen"
	for _, fixture := range []struct {
		cluster string
		tag     string
		score   int32
	}{
		{cluster: "dev", tag: "prerelease@sha256:dev", score: 5},
		{cluster: "prod", tag: "release@sha256:prod", score: 274},
	} {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{
			Name: imageName, Tag: fixture.tag, Metadata: map[string]string{},
		}))
		_, err := db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{
			ImageName: imageName, ImageTag: fixture.tag, RiskScore: fixture.score,
		})
		require.NoError(t, err)
		_, err = db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: "amt-pdfgen", WorkloadType: "app", Namespace: "amt",
			Cluster: fixture.cluster, ImageName: imageName, ImageTag: fixture.tag,
		})
		require.NoError(t, err)
	}

	_, err := pool.Exec(ctx, `UPDATE images SET state = 'updated' WHERE name = $1`, imageName)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		UPDATE vulnerability_summary
		SET updated_at = NOW() - INTERVAL '1 hour'
		WHERE image_name = $1 AND image_tag = 'prerelease@sha256:dev'
	`, imageName)
	require.NoError(t, err)
	for _, phase := range []struct {
		name   string
		state  string
		status vulnerabilities.SbomStatus
	}{
		{"before resync", "updated", vulnerabilities.SbomStatus_SBOM_STATUS_READY},
		{"during resync", "resync", vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING},
		{"after resync", "updated", vulnerabilities.SbomStatus_SBOM_STATUS_READY},
	} {
		t.Run(phase.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `UPDATE images SET state = $2 WHERE name = $1`, imageName, phase.state)
			require.NoError(t, err)
			for _, expected := range []struct {
				cluster string
				tag     string
				score   int32
			}{
				{"dev", "prerelease@sha256:dev", 5},
				{"prod", "release@sha256:prod", 274},
			} {
				options := []vulnerabilities.Option{
					vulnerabilities.ClusterFilter(expected.cluster),
					vulnerabilities.NamespaceFilter("amt"),
					vulnerabilities.WorkloadFilter("amt-pdfgen"),
				}
				list, err := client.ListVulnerabilitySummaries(ctx, options...)
				require.NoError(t, err)
				require.Len(t, list.GetNodes(), 1)
				node := list.GetNodes()[0]
				require.NotNil(t, node.GetVulnerabilitySummary())
				assert.Equal(t, expected.cluster, node.GetWorkload().GetCluster())
				assert.Equal(t, expected.tag, node.GetWorkload().GetImageTag())
				assert.Equal(t, expected.score, node.GetVulnerabilitySummary().GetRiskScore())
				assert.Empty(t, node.GetVulnerabilitySummary().GetStaleImageTag())
				assert.Equal(t, phase.status, node.GetSbomStatus().GetStatus())
				summary, err := client.GetVulnerabilitySummary(ctx, options...)
				require.NoError(t, err)
				assert.Equal(t, expected.score, summary.GetVulnerabilitySummary().GetRiskScore())
			}
		})
	}
}

func TestServer_SummariesNeverUseAnotherImageTag(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	for _, tc := range []struct {
		name           string
		imageState     string
		currentSummary bool
		latestTag      string
		wantScore      int32
		wantStaleTag   string
		wantSummary    bool
	}{
		{"initialized dev without summary does not use prod", "initialized", false, "prod", 0, "", false},
		{"resync dev without summary does not use prod", "resync", false, "prod", 0, "", false},
		{"resync dev without summary does not use previous dev", "resync", false, "previous-dev", 0, "", false},
		{"existing dev summary wins over newer prod", "resync", true, "prod", 5, "", true},
		{"ready dev without summary does not use prod", "updated", false, "prod", 0, "", false},
		{"failed dev without summary does not use prod", "failed", false, "prod", 0, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			imageName := "registry.example/" + t.Name()
			for _, image := range []struct {
				tag   string
				state string
				score int32
			}{
				{"previous-dev", "unused", 5},
				{"prod", "updated", 274},
				{"current-dev", tc.imageState, 5},
			} {
				require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{
					Name: imageName, Tag: image.tag, Metadata: map[string]string{},
				}))
				_, err := pool.Exec(ctx, `UPDATE images SET state = $3 WHERE name = $1 AND tag = $2`,
					imageName, image.tag, image.state)
				require.NoError(t, err)
				if image.tag != "current-dev" || tc.currentSummary {
					_, err = db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{
						ImageName: imageName, ImageTag: image.tag, RiskScore: image.score,
					})
					require.NoError(t, err)
				}
			}
			_, err := pool.Exec(ctx, `
					UPDATE vulnerability_summary
					SET updated_at = CASE WHEN image_tag = $2
						THEN NOW() ELSE NOW() - INTERVAL '1 hour' END
					WHERE image_name = $1
				`, imageName, tc.latestTag)
			require.NoError(t, err)
			for _, workload := range []struct {
				cluster string
				tag     string
			}{
				{"dev", "current-dev"},
				{"prod", "prod"},
			} {
				_, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
					Name: "amt-pdfgen", WorkloadType: "app", Namespace: tc.name,
					Cluster: workload.cluster, ImageName: imageName, ImageTag: workload.tag,
				})
				require.NoError(t, err)
			}

			options := []vulnerabilities.Option{
				vulnerabilities.ClusterFilter("dev"),
				vulnerabilities.NamespaceFilter(tc.name),
				vulnerabilities.WorkloadFilter("amt-pdfgen"),
			}
			list, err := client.ListVulnerabilitySummaries(ctx, options...)
			require.NoError(t, err)
			require.Len(t, list.GetNodes(), 1)
			node := list.GetNodes()[0]
			assert.Equal(t, "dev", node.GetWorkload().GetCluster())
			assert.Equal(t, "current-dev", node.GetWorkload().GetImageTag())
			if tc.wantSummary {
				require.NotNil(t, node.GetVulnerabilitySummary())
				assert.Equal(t, tc.wantScore, node.GetVulnerabilitySummary().GetRiskScore())
				assert.Equal(t, tc.wantStaleTag, node.GetVulnerabilitySummary().GetStaleImageTag())
			} else {
				assert.Nil(t, node.GetVulnerabilitySummary())
			}
			if tc.imageState == "initialized" || tc.imageState == "resync" {
				assert.Equal(t, vulnerabilities.SbomStatus_SBOM_STATUS_PROCESSING, node.GetSbomStatus().GetStatus())
			}

			imageSummary, err := client.GetVulnerabilitySummaryForImage(ctx, imageName, "current-dev")
			require.NoError(t, err)
			require.Len(t, imageSummary.GetWorkloadRef(), 1)
			assert.Equal(t, "dev", imageSummary.GetWorkloadRef()[0].GetCluster())
			assert.Equal(t, node.GetSbomStatus().GetStatus(), imageSummary.GetSbomStatus().GetStatus())
			if tc.wantSummary {
				require.NotNil(t, imageSummary.GetVulnerabilitySummary())
				assert.Equal(t, tc.wantScore, imageSummary.GetVulnerabilitySummary().GetRiskScore())
				assert.Empty(t, imageSummary.GetVulnerabilitySummary().GetStaleImageTag())
			} else {
				assert.Nil(t, imageSummary.GetVulnerabilitySummary())
			}

			summary, err := client.GetVulnerabilitySummary(ctx, options...)
			require.NoError(t, err)
			assert.Equal(t, tc.wantScore, summary.GetVulnerabilitySummary().GetRiskScore())
			if !tc.wantSummary {
				require.NotNil(t, summary.GetVulnerabilitySummary())
				assert.False(t, summary.GetVulnerabilitySummary().GetHasSbom())
				assert.Nil(t, summary.GetVulnerabilitySummary().GetLastUpdated())
				assert.Zero(t, summary.GetSbomCount())
			}
			batch, err := client.GetVulnerabilitySummaries(ctx, []string{tc.name},
				vulnerabilities.ClusterFilter("dev"),
				vulnerabilities.WorkloadFilter("amt-pdfgen"))
			require.NoError(t, err)
			require.Contains(t, batch.GetSummaries(), tc.name)
			assert.Equal(t, tc.wantScore, batch.GetSummaries()[tc.name].GetVulnerabilitySummary().GetRiskScore())
			if !tc.wantSummary {
				require.NotNil(t, batch.GetSummaries()[tc.name].GetVulnerabilitySummary())
				assert.False(t, batch.GetSummaries()[tc.name].GetVulnerabilitySummary().GetHasSbom())
				assert.Nil(t, batch.GetSummaries()[tc.name].GetVulnerabilitySummary().GetLastUpdated())
				assert.Zero(t, batch.GetSummaries()[tc.name].GetSbomCount())
			}

			metrics, err := db.ListVulnerabilitySummariesForMetrics(ctx, nil)
			require.NoError(t, err)
			matched := false
			for _, row := range metrics {
				if row.Namespace == tc.name && row.Cluster == "dev" {
					matched = true
					assert.Equal(t, "current-dev", row.CurrentImageTag)
					assert.Equal(t, tc.wantScore, row.RiskScore)
				}
			}
			require.True(t, matched)
		})
	}
}
