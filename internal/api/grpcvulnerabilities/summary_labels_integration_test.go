//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type summaryLabelFixture struct {
	name   string
	labels map[string]string
	risk   int32
}

type summaryLabelFilterCase struct {
	name    string
	filters []*vulnerabilities.LabelFilter
	want    []string
}

func TestServer_SummaryLabels(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()
	for _, fixture := range []summaryLabelFixture{
		{"empty", map[string]string{"owner": ""}, 10},
		{"alpha-low", map[string]string{"owner": "alpha", "region": "prod"}, 5},
		{"alpha-b", map[string]string{"owner": "alpha", "region": "dev"}, 20},
		{"alpha-a", map[string]string{"owner": "alpha", "region": "dev"}, 20},
		{"zebra", map[string]string{"owner": "zebra"}, 30},
		{"helm", map[string]string{"app.kubernetes.io/managed-by": "helm"}, 40},
		{"missing", nil, 100},
	} {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: fixture.name, Tag: "v1"}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = 'updated' WHERE name = $1`, fixture.name)
		require.NoError(t, err)
		_, err = db.CreateVulnerabilitySummary(ctx, sql.CreateVulnerabilitySummaryParams{
			ImageName: fixture.name, ImageTag: "v1", RiskScore: fixture.risk,
		})
		require.NoError(t, err)
		id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: fixture.name, WorkloadType: "app", Namespace: "labels", Cluster: "dev",
			ImageName: fixture.name, ImageTag: "v1", Labels: typeext.MapStringString(fixture.labels),
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: id, State: sql.WorkloadStateUpdated}))
	}
	names := func(response *vulnerabilities.ListVulnerabilitySummariesResponse) []string {
		out := make([]string, 0, len(response.GetNodes()))
		for _, node := range response.GetNodes() {
			out = append(out, node.GetWorkload().GetName())
		}
		return out
	}
	for _, tt := range []summaryLabelFilterCase{
		{"without filter", nil, []string{"alpha-a", "alpha-b", "alpha-low", "empty", "helm", "missing", "zebra"}},
		{"key exists", []*vulnerabilities.LabelFilter{{Key: "owner"}}, []string{"alpha-a", "alpha-b", "alpha-low", "empty", "zebra"}},
		{"exact empty", []*vulnerabilities.LabelFilter{{Key: "owner", Value: new("")}}, []string{"empty"}},
		{"and filters", []*vulnerabilities.LabelFilter{{Key: "owner", Value: new("alpha")}, {Key: "region", Value: new("dev")}}, []string{"alpha-a", "alpha-b"}},
		{"value-dependent platform key", []*vulnerabilities.LabelFilter{{Key: "app.kubernetes.io/managed-by"}}, []string{"helm"}},
		{"missing key", []*vulnerabilities.LabelFilter{{Key: "absent"}}, []string{}},
		{"contradictory filters", []*vulnerabilities.LabelFilter{{Key: "owner", Value: new("alpha")}, {Key: "owner", Value: new("zebra")}}, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.ListVulnerabilitySummaries(ctx, vulnerabilities.NamespaceFilter("labels"),
				vulnerabilities.LabelsFilter(tt.filters...), vulnerabilities.Order(vulnerabilities.OrderByWorkload, vulnerabilities.Direction_ASC))
			require.NoError(t, err)
			assert.Equal(t, tt.want, names(response))
			assert.Equal(t, int64(len(tt.want)), response.GetPageInfo().GetTotalCount())
			aggregate, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter("labels"),
				vulnerabilities.LabelsFilter(tt.filters...))
			require.NoError(t, err)
			assert.Equal(t, int32(len(tt.want)), aggregate.GetWorkloadCount())
			assert.Equal(t, int32(len(tt.want)), aggregate.GetSbomCount())
			var risk int32
			for _, node := range response.GetNodes() {
				risk += node.GetVulnerabilitySummary().GetRiskScore()
			}
			assert.Equal(t, risk, aggregate.GetVulnerabilitySummary().GetRiskScore())
			coverage := float32(0)
			if len(tt.want) > 0 {
				coverage = 100
			}
			assert.Equal(t, coverage, aggregate.GetCoverage())
		})
	}
	t.Run("aggregate combines labels with existing filters", func(t *testing.T) {
		_, err := pool.Exec(ctx, `UPDATE vulnerability_summary SET top_risk_tier = 2, kev_count = 1 WHERE image_name = 'alpha-a'`)
		require.NoError(t, err)
		for _, option := range []vulnerabilities.Option{
			vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH),
			vulnerabilities.KevFilter(true),
		} {
			response, err := client.GetVulnerabilitySummary(ctx,
				vulnerabilities.NamespaceFilter("labels"), vulnerabilities.ClusterFilter("dev"),
				vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner", Value: new("alpha")}), option)
			require.NoError(t, err)
			assert.Equal(t, int32(1), response.GetWorkloadCount())
			assert.Equal(t, int32(20), response.GetVulnerabilitySummary().GetRiskScore())
		}
		response, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter("labels"),
			vulnerabilities.ClusterFilter("missing"), vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner"}))
		require.NoError(t, err)
		assert.Zero(t, response.GetWorkloadCount())
	})
	t.Run("aggregate coverage includes matching workloads without an SBOM", func(t *testing.T) {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: "no-sbom", Tag: "v1"}))
		for _, image := range []string{"alpha-low", "no-sbom"} {
			id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
				Name: image, WorkloadType: "app", Namespace: "coverage-labels", Cluster: "dev",
				ImageName: image, ImageTag: "v1", Labels: typeext.MapStringString{"owner": "coverage"},
			})
			require.NoError(t, err)
			require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: id, State: sql.WorkloadStateUpdated}))
		}
		response, err := client.GetVulnerabilitySummary(ctx, vulnerabilities.NamespaceFilter("coverage-labels"),
			vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner", Value: new("coverage")}))
		require.NoError(t, err)
		assert.Equal(t, int32(2), response.GetWorkloadCount())
		assert.Equal(t, int32(1), response.GetSbomCount())
		assert.Equal(t, float32(50), response.GetCoverage())
		assert.Equal(t, int32(5), response.GetVulnerabilitySummary().GetRiskScore())
	})
	t.Run("filtering and ordering happen before pagination", func(t *testing.T) {
		options := []vulnerabilities.Option{
			vulnerabilities.NamespaceFilter("labels"),
			vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner", Value: new("alpha")}),
			vulnerabilities.Order(vulnerabilities.OrderByWorkload, vulnerabilities.Direction_ASC), vulnerabilities.Limit(1),
		}
		for repeat := 0; repeat < 2; repeat++ {
			got := []string{}
			for offset := int32(0); offset < 3; offset++ {
				response, err := client.ListVulnerabilitySummaries(ctx, append(options, vulnerabilities.Offset(offset))...)
				require.NoError(t, err)
				assert.Equal(t, int64(3), response.GetPageInfo().GetTotalCount())
				assert.Equal(t, offset < 2, response.GetPageInfo().GetHasNextPage())
				got = append(got, names(response)...)
			}
			assert.Equal(t, []string{"alpha-a", "alpha-b", "alpha-low"}, got)
		}
	})
	t.Run("metadata-only changes persist without changing image or scan state", func(t *testing.T) {
		params := sql.InitializeWorkloadParams{
			Name: "alpha-a", WorkloadType: "app", Namespace: "labels", Cluster: "dev",
			ImageName: "alpha-a", ImageTag: "v1", Labels: typeext.MapStringString{"owner": "alpha", "region": "dev"},
		}
		stored, err := db.GetWorkload(ctx, sql.GetWorkloadParams{Name: params.Name, WorkloadType: params.WorkloadType, Namespace: params.Namespace, Cluster: params.Cluster})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: stored.ID, State: sql.WorkloadStateUpdated}))
		for _, labels := range []typeext.MapStringString{{"owner": "new"}, nil} {
			params.Labels = labels
			id, err := db.InitializeWorkload(ctx, params)
			require.NoError(t, err)
			assert.False(t, id.Valid, "metadata changes must not start a scan")
			require.NoError(t, db.UpdateWorkloadLabels(ctx, sql.UpdateWorkloadLabelsParams{
				Name: params.Name, WorkloadType: params.WorkloadType, Namespace: params.Namespace, Cluster: params.Cluster,
				ImageName: params.ImageName, ImageTag: params.ImageTag, Labels: labels,
			}))
			workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{Name: params.Name, WorkloadType: params.WorkloadType, Namespace: params.Namespace, Cluster: params.Cluster})
			require.NoError(t, err)
			assert.Equal(t, sql.WorkloadStateUpdated, workload.State)
			assert.Equal(t, "v1", workload.ImageTag)
			response, err := client.ListVulnerabilitySummaries(ctx, vulnerabilities.NamespaceFilter("labels"), vulnerabilities.WorkloadFilter(params.Name))
			require.NoError(t, err)
			require.Len(t, response.GetNodes(), 1)
			if labels == nil {
				assert.Empty(t, workload.Labels)
				assert.Empty(t, response.Nodes[0].GetWorkload().GetLabels())
			} else {
				assert.Equal(t, "new", workload.Labels["owner"])
				assert.Equal(t, map[string]string{"owner": "new"}, response.Nodes[0].GetWorkload().GetLabels())
			}
		}
	})
	t.Run("resync preserves labels unless metadata explicitly clears them", func(t *testing.T) {
		key := sql.GetWorkloadParams{Name: "zebra", WorkloadType: "app", Namespace: "labels", Cluster: "dev"}
		stored, err := db.GetWorkload(ctx, key)
		require.NoError(t, err)
		for _, labels := range []typeext.MapStringString{nil, {}} {
			require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: stored.ID, State: sql.WorkloadStateResync}))
			id, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
				Name: key.Name, WorkloadType: key.WorkloadType, Namespace: key.Namespace, Cluster: key.Cluster,
				ImageName: "zebra", ImageTag: "v1", Labels: labels,
			})
			require.NoError(t, err)
			require.Equal(t, stored.ID, id)
			workload, err := db.GetWorkload(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, sql.WorkloadStateProcessing, workload.State)
			assert.Equal(t, "v1", workload.ImageTag)
			if labels == nil {
				assert.Equal(t, typeext.MapStringString{"owner": "zebra"}, workload.Labels)
			} else {
				assert.Empty(t, workload.Labels)
			}
		}
	})
}
