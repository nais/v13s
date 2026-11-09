//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/database/typeext"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestServer_WorkloadSelection(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const commonCVE = "CVE-SELECTION-1"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: commonCVE, Severity: int32(vulnerabilities.Severity_HIGH), Refs: map[string]string{}},
		{CveID: "CVE-SELECTION-2", Severity: int32(vulnerabilities.Severity_HIGH), Refs: map[string]string{}},
		{CveID: "CVE-SELECTION-3", Severity: int32(vulnerabilities.Severity_HIGH), Refs: map[string]string{}},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })
	_, err := pool.Exec(ctx, `UPDATE cve SET has_kev_entry = TRUE WHERE cve_id = $1`, commonCVE)
	require.NoError(t, err)

	for _, image := range []struct {
		name string
		tag  string
		cves []string
		pkgs []string
	}{
		{"shared", "v1", []string{commonCVE, commonCVE}, []string{"pkg-a", "pkg-b"}},
		{"other", "v2", []string{commonCVE, "CVE-SELECTION-2"}, []string{"pkg-c", "pkg-d"}},
		{"excluded", "v1", []string{"CVE-SELECTION-3"}, []string{"pkg-e"}},
	} {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image.name, Tag: image.tag}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = 'updated' WHERE name = $1 AND tag = $2`, image.name, image.tag)
		require.NoError(t, err)
		for i, id := range image.cves {
			db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
				{ImageName: image.name, ImageTag: image.tag, Package: image.pkgs[i], CveID: id, Source: "test"},
			}).Exec(func(_ int, err error) { require.NoError(t, err) })
		}
		require.NoError(t, db.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
			ImageName: image.name, ImageTag: image.tag,
		}))
	}

	selected := []*vulnerabilities.WorkloadIdentity{
		{Cluster: "dev", Namespace: "team-a", Name: "same", Type: "app"},
		{Cluster: "prod", Namespace: "team-b", Name: "same", Type: "app"},
		{Cluster: "dev", Namespace: "team-a", Name: "second", Type: "app"},
	}
	customType := &vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team-a", Name: "same", Type: "daemonset"}
	for _, fixture := range []struct {
		identity *vulnerabilities.WorkloadIdentity
		image    string
		tag      string
		owner    string
	}{
		{selected[0], "shared", "v1", "alpha"},
		{selected[1], "shared", "v1", "beta"},
		{selected[2], "other", "v2", "beta"},
		{customType, "shared", "v1", "alpha"},
		{&vulnerabilities.WorkloadIdentity{Cluster: "prod", Namespace: "team-a", Name: "same", Type: "app"}, "excluded", "v1", "alpha"},
		{&vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team-b", Name: "same", Type: "app"}, "shared", "v1", "alpha"},
		{&vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team-a", Name: "same", Type: "job"}, "shared", "v1", "alpha"},
		{&vulnerabilities.WorkloadIdentity{Cluster: "dev", Namespace: "team-a", Name: "third", Type: "app"}, "shared", "v1", "alpha"},
	} {
		id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: fixture.identity.Name, Cluster: fixture.identity.Cluster,
			Namespace: fixture.identity.Namespace, WorkloadType: fixture.identity.Type,
			ImageName: fixture.image, ImageTag: fixture.tag, Labels: typeext.MapStringString{"owner": fixture.owner},
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: id, State: sql.WorkloadStateUpdated}))
	}
	require.NoError(t, db.RefreshCveWorkloadCounts(ctx))

	for _, tt := range []struct {
		name      string
		opts      []vulnerabilities.Option
		workloads int32
		high      int32
		cves      int
		findings  int
		impact    *vulnerabilities.CveImpact
	}{
		{"absent", nil, 7, 13, 3, 11, &vulnerabilities.CveImpact{WorkloadCount: 6, ImageCount: 2, PackageCount: 3}},
		{"selected", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...)}, 3, 6, 2, 5, &vulnerabilities.CveImpact{WorkloadCount: 3, ImageCount: 2, PackageCount: 3}},
		{"empty", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter()}, 0, 0, 0, 0, &vulnerabilities.CveImpact{}},
		{"missing", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(&vulnerabilities.WorkloadIdentity{Cluster: "missing", Namespace: "team-a", Name: "same", Type: "app"})}, 0, 0, 0, 0, &vulnerabilities.CveImpact{}},
		{"duplicates", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(append(selected, selected[0])...)}, 3, 6, 2, 5, &vulnerabilities.CveImpact{WorkloadCount: 3, ImageCount: 2, PackageCount: 3}},
		{"namespace intersection", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...), vulnerabilities.NamespaceFilter("team-a")}, 2, 4, 2, 3, &vulnerabilities.CveImpact{WorkloadCount: 2, ImageCount: 2, PackageCount: 3}},
		{"cluster intersection", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...), vulnerabilities.ClusterFilter("prod")}, 1, 2, 1, 2, &vulnerabilities.CveImpact{WorkloadCount: 1, ImageCount: 1, PackageCount: 2}},
		{"name intersection", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...), vulnerabilities.WorkloadFilter("same")}, 2, 4, 1, 4, &vulnerabilities.CveImpact{WorkloadCount: 2, ImageCount: 1, PackageCount: 2}},
		{"type intersection", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...), vulnerabilities.WorkloadTypeFilter("job")}, 0, 0, 0, 0, &vulnerabilities.CveImpact{}},
		{"custom type", []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(customType)}, 1, 2, 1, 2, &vulnerabilities.CveImpact{WorkloadCount: 1, ImageCount: 1, PackageCount: 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			summaries, err := client.ListVulnerabilitySummaries(ctx, tt.opts...)
			require.NoError(t, err)
			assert.Len(t, summaries.GetNodes(), int(tt.workloads))
			assert.Equal(t, int64(tt.workloads), summaries.GetPageInfo().GetTotalCount())
			if selection := vulnerabilities.GetOptions(tt.opts...).WorkloadSelection; selection != nil {
				for _, node := range summaries.GetNodes() {
					w := node.GetWorkload()
					identity := &vulnerabilities.WorkloadIdentity{Cluster: w.Cluster, Namespace: w.Namespace, Name: w.Name, Type: w.Type}
					matched := false
					for _, selected := range selection.GetWorkloads() {
						matched = matched || proto.Equal(identity, selected)
					}
					assert.True(t, matched, "unexpected workload %v", identity)
				}
			}
			aggregate, err := client.GetVulnerabilitySummary(ctx, tt.opts...)
			require.NoError(t, err)
			assert.Equal(t, tt.workloads, aggregate.GetWorkloadCount())
			assert.Equal(t, tt.workloads, aggregate.GetSbomCount())
			assert.Equal(t, tt.high, aggregate.GetVulnerabilitySummary().GetHigh())

			bulkOpts := append([]vulnerabilities.Option{}, tt.opts...)
			filter := vulnerabilities.GetFilter(tt.opts...)
			namespaces := []string{"team-a", "team-b"}
			if filter.Namespace != nil {
				namespaces = []string{filter.GetNamespace()}
				bulkOpts = []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...)}
			}
			bulk, err := client.GetVulnerabilitySummaries(ctx, namespaces, bulkOpts...)
			require.NoError(t, err)
			require.Len(t, bulk.GetSummaries(), len(namespaces))
			var count, high int32
			for _, namespace := range namespaces {
				count += bulk.GetSummaries()[namespace].GetWorkloadCount()
				high += bulk.GetSummaries()[namespace].GetVulnerabilitySummary().GetHigh()
			}
			assert.Equal(t, tt.workloads, count)
			assert.Equal(t, tt.high, high)

			cves, err := client.ListCveSummaries(ctx, tt.opts...)
			require.NoError(t, err)
			assert.Len(t, cves.GetNodes(), tt.cves)
			assert.Equal(t, int64(tt.cves), cves.GetPageInfo().GetTotalCount())
			for _, cve := range cves.GetNodes() {
				if cve.GetCve().GetId() == commonCVE {
					assert.Equal(t, tt.impact.GetWorkloadCount(), cve.GetAffectedWorkloads())
				}
			}
			findings, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{commonCVE}}, tt.opts...)
			require.NoError(t, err)
			assert.Len(t, findings.GetNodes(), tt.findings)
			assert.Equal(t, int64(tt.findings), findings.GetPageInfo().GetTotalCount())
			assert.True(t, proto.Equal(tt.impact, findings.GetImpact()), "want %v, got %v", tt.impact, findings.GetImpact())
		})
	}

	t.Run("filtered pagination retains totals past the end", func(t *testing.T) {
		for offset := int32(0); offset <= 5; offset++ {
			opts := []vulnerabilities.Option{vulnerabilities.WorkloadsFilter(selected...), vulnerabilities.Limit(1), vulnerabilities.Offset(offset)}
			summaries, err := client.ListVulnerabilitySummaries(ctx, opts...)
			require.NoError(t, err)
			assert.Equal(t, int64(3), summaries.GetPageInfo().GetTotalCount())
			assert.Equal(t, offset < 2, summaries.GetPageInfo().GetHasNextPage())
			assert.Equal(t, offset > 0, summaries.GetPageInfo().GetHasPreviousPage())
			assert.Equal(t, offset < 3, len(summaries.GetNodes()) == 1)
			cves, err := client.ListCveSummaries(ctx, opts...)
			require.NoError(t, err)
			assert.Equal(t, int64(2), cves.GetPageInfo().GetTotalCount())
			assert.Equal(t, offset < 1, cves.GetPageInfo().GetHasNextPage())
			assert.Equal(t, offset < 2, len(cves.GetNodes()) == 1)
			findings, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{commonCVE}}, opts...)
			require.NoError(t, err)
			assert.Equal(t, int64(5), findings.GetPageInfo().GetTotalCount())
			assert.Equal(t, offset < 4, findings.GetPageInfo().GetHasNextPage())
			assert.Equal(t, offset < 5, len(findings.GetNodes()) == 1)
			assert.True(t, proto.Equal(&vulnerabilities.CveImpact{WorkloadCount: 3, ImageCount: 2, PackageCount: 3}, findings.GetImpact()))
		}
	})

	t.Run("selection intersects labels and risk filters", func(t *testing.T) {
		opts := []vulnerabilities.Option{
			vulnerabilities.WorkloadsFilter(selected...),
			vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner", Value: new("alpha")}),
			vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_HIGH),
			vulnerabilities.KevFilter(true),
		}
		summaries, err := client.ListVulnerabilitySummaries(ctx, opts...)
		require.NoError(t, err)
		require.Len(t, summaries.GetNodes(), 1)
		assert.Equal(t, "dev", summaries.GetNodes()[0].GetWorkload().GetCluster())
		assert.Equal(t, "team-a", summaries.GetNodes()[0].GetWorkload().GetNamespace())
		aggregate, err := client.GetVulnerabilitySummary(ctx, opts...)
		require.NoError(t, err)
		assert.Equal(t, int32(1), aggregate.GetWorkloadCount())
	})

	t.Run("image changes keep the identity selected without a counts refresh", func(t *testing.T) {
		id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Cluster: selected[2].Cluster, Namespace: selected[2].Namespace, Name: selected[2].Name, WorkloadType: selected[2].Type,
			ImageName: "shared", ImageTag: "v1",
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: id, State: sql.WorkloadStateUpdated}))
		cves, err := client.ListCveSummaries(ctx, vulnerabilities.WorkloadsFilter(selected...))
		require.NoError(t, err)
		require.Len(t, cves.GetNodes(), 1)
		assert.Equal(t, commonCVE, cves.GetNodes()[0].GetCve().GetId())
		assert.Equal(t, int32(3), cves.GetNodes()[0].GetAffectedWorkloads())
		findings, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{commonCVE}},
			vulnerabilities.WorkloadsFilter(selected...))
		require.NoError(t, err)
		assert.Equal(t, int64(6), findings.GetPageInfo().GetTotalCount())
		assert.True(t, proto.Equal(&vulnerabilities.CveImpact{WorkloadCount: 3, ImageCount: 1, PackageCount: 2}, findings.GetImpact()))
	})
}
