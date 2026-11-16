//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestServer_SummaryPackageType(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES
			('mixed-a', 'v1', 'updated'), ('mixed-a', 'old', 'updated'),
			('mixed-b', 'v1', 'updated'), ('clean', 'v1', 'updated'),
			('apk-only', 'v1', 'updated'), ('missing', 'v1', 'initialized'), ('outside', 'v1', 'updated');
		INSERT INTO workloads (name, workload_type, namespace, cluster, image_name, image_tag, state, labels) VALUES
			('app-a', 'app', 'packages', 'dev', 'mixed-a', 'v1', 'updated', '{"owner":"a"}'),
			('job-a', 'job', 'packages', 'dev', 'mixed-a', 'v1', 'updated', '{"owner":"a"}'),
			('app-b', 'app', 'packages', 'dev', 'mixed-b', 'v1', 'updated', '{"owner":"b"}'),
			('clean', 'app', 'packages', 'dev', 'clean', 'v1', 'updated', '{}'),
			('apk-only', 'app', 'packages', 'dev', 'apk-only', 'v1', 'updated', '{}'),
			('missing', 'app', 'packages', 'dev', 'missing', 'v1', 'no_attestation', '{}'),
			('failed', 'app', 'packages', 'dev', 'mixed-a', 'v1', 'failed', '{}'),
			('no-attestation', 'app', 'packages', 'dev', 'mixed-a', 'v1', 'no_attestation', '{}'),
			('outside', 'app', 'other', 'prod', 'outside', 'v1', 'updated', '{}');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs, epss_percentile, has_kev_entry)
		SELECT id, '', '', '', severity, '{}', percentile, kev FROM (VALUES
			('CVE-elevated', 1, 0.92::FLOAT8, FALSE),
			('GHSA-alias', 4, NULL, FALSE),
			('CVE-medium', 2, NULL, FALSE),
			('CVE-critical', 0, NULL, FALSE),
			('CVE-kev', 0, NULL, TRUE)
		) AS c(id, severity, percentile, kev);
		INSERT INTO cve_alias (alias, canonical_cve_id) VALUES ('GHSA-alias', 'CVE-elevated');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version) VALUES
			('mixed-a', 'v1', 'pkg:npm/@scope/elevated@1', 'CVE-elevated', 'test', ''),
			('mixed-a', 'v1', 'pkg:npm/@scope/elevated@1', 'GHSA-alias', 'test', ''),
			('mixed-a', 'v1', 'pkg:npm/medium@1', 'CVE-medium', 'test', ''),
			('mixed-a', 'v1', 'pkg:npm/suppressed@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:gem/suppressed@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:apk/base@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:npm-extra/other@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:npm2/other@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:NPM/other@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'not-a-purl', 'CVE-kev', 'test', ''),
			('mixed-a', 'v1', 'pkg:maven/example/npm@1', 'CVE-kev', 'test', ''),
			('mixed-a', 'old', 'pkg:cargo/old@1', 'CVE-kev', 'test', ''),
			('mixed-b', 'v1', 'pkg:npm/critical@1', 'CVE-critical', 'test', ''),
			('mixed-b', 'v1', 'pkg:maven/one@1', 'CVE-critical', 'test', ''),
			('mixed-b', 'v1', 'pkg:maven/two@1', 'CVE-critical', 'test', ''),
			('mixed-b', 'v1', 'pkg:maven/three@1', 'CVE-critical', 'test', ''),
			('apk-only', 'v1', 'pkg:apk/base@1', 'CVE-kev', 'test', ''),
			('outside', 'v1', 'pkg:pypi/private@1', 'CVE-kev', 'test', '');
		INSERT INTO suppressed_vulnerabilities (image_name, package, cve_id, suppressed) VALUES
			('mixed-a', 'pkg:npm/suppressed@1', 'CVE-kev', TRUE),
			('mixed-a', 'pkg:gem/suppressed@1', 'CVE-kev', TRUE);
	`)
	require.NoError(t, err)
	for _, image := range []string{"mixed-a", "mixed-b", "clean", "apk-only"} {
		require.NoError(t, db.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{
			ImageName: image, ImageTag: "v1",
		}))
	}
	options := []vulnerabilities.Option{
		vulnerabilities.NamespaceFilter("packages"), vulnerabilities.ClusterFilter("dev"),
		vulnerabilities.Order(vulnerabilities.OrderByWorkload, vulnerabilities.Direction_ASC),
	}
	types := []*vulnerabilities.PackageTypeCount{
		{Value: "apk", Count: 2},
		{Value: "gem", Count: 1},
		{Value: "maven", Count: 4},
		{Value: "npm", Count: 4},
		{Value: "npm-extra", Count: 1},
		{Value: "npm2", Count: 1},
	}
	baseline, err := client.ListVulnerabilitySummaries(ctx, options...)
	require.NoError(t, err)
	require.Len(t, baseline.GetNodes(), 8)
	assert.Empty(t, cmp.Diff(types, baseline.GetPackageTypeCounts(), protocmp.Transform()))
	nodes := map[string]*vulnerabilities.WorkloadSummary{}
	for _, node := range baseline.GetNodes() {
		nodes[node.GetWorkload().GetName()] = node
	}
	assert.Equal(t, int32(8), nodes["app-a"].GetVulnerabilitySummary().GetTotal())
	assert.Equal(t, int32(1), nodes["app-a"].GetVulnerabilitySummary().GetHigh())
	assert.Equal(t, int32(6), nodes["app-a"].GetVulnerabilitySummary().GetKevCount())

	t.Run("omitting counts preserves filtered workloads and pagination over grpc", func(t *testing.T) {
		filteredOptions := append(options, vulnerabilities.PackageTypeFilter("npm"), vulnerabilities.Limit(1))
		withCounts, err := client.ListVulnerabilitySummaries(ctx, append(filteredOptions, vulnerabilities.IncludePackageTypeCounts(true))...)
		require.NoError(t, err)
		assert.NotEmpty(t, withCounts.GetPackageTypeCounts())
		withoutCounts, err := client.ListVulnerabilitySummaries(ctx, append(filteredOptions, vulnerabilities.IncludePackageTypeCounts(false))...)
		require.NoError(t, err)
		assert.Empty(t, withoutCounts.GetPackageTypeCounts())
		assert.Empty(t, cmp.Diff(withCounts.GetNodes(), withoutCounts.GetNodes(), protocmp.Transform()))
		assert.True(t, proto.Equal(withCounts.GetPageInfo(), withoutCounts.GetPageInfo()))
	})

	t.Run("exact membership keeps summaries and workload status unchanged", func(t *testing.T) {
		for _, tc := range []struct {
			packageType string
			want        []string
		}{
			{"npm", []string{"app-a", "app-b", "failed", "job-a", "no-attestation"}},
			{"apk", []string{"apk-only", "app-a", "failed", "job-a", "no-attestation"}},
			{"npm2", []string{"app-a", "failed", "job-a", "no-attestation"}},
			{"gem", []string{"app-a", "failed", "job-a", "no-attestation"}},
			{"unknown", []string{}},
		} {
			response, err := client.ListVulnerabilitySummaries(ctx, append(options, vulnerabilities.PackageTypeFilter(tc.packageType))...)
			require.NoError(t, err)
			got := []string{}
			for _, node := range response.GetNodes() {
				name := node.GetWorkload().GetName()
				got = append(got, name)
				assert.True(t, proto.Equal(nodes[name], node), "summary changed for %s", name)
			}
			assert.Equal(t, tc.want, got)
			assert.Equal(t, int64(len(tc.want)), response.GetPageInfo().GetTotalCount())
			assert.Empty(t, cmp.Diff(types, response.GetPackageTypeCounts(), protocmp.Transform()))
		}
	})

	t.Run("filter choices respect current image and workload scope", func(t *testing.T) {
		for _, filter := range []vulnerabilities.Option{
			vulnerabilities.WorkloadFilter("app-b"),
			vulnerabilities.ImageFilter("mixed-b", "v1"),
			vulnerabilities.LabelsFilter(&vulnerabilities.LabelFilter{Key: "owner", Value: new("b")}),
		} {
			response, err := client.ListVulnerabilitySummaries(ctx, append(options, filter)...)
			require.NoError(t, err)
			assert.Empty(t, cmp.Diff([]*vulnerabilities.PackageTypeCount{
				{Value: "maven", Count: 3}, {Value: "npm", Count: 1},
			}, response.GetPackageTypeCounts(), protocmp.Transform()))
		}
		for _, filter := range []vulnerabilities.Option{
			vulnerabilities.NamespaceFilter("empty"), vulnerabilities.ClusterFilter("empty"),
			vulnerabilities.ImageFilter("mixed-a", "old"),
		} {
			response, err := client.ListVulnerabilitySummaries(ctx, append(options, filter)...)
			require.NoError(t, err)
			assert.Empty(t, response.GetNodes())
			assert.Empty(t, response.GetPackageTypeCounts())
		}
		jobs, err := client.ListVulnerabilitySummaries(ctx, append(options, vulnerabilities.WorkloadTypeFilter("job"))...)
		require.NoError(t, err)
		require.Len(t, jobs.GetNodes(), 1)
		assert.Equal(t, "job-a", jobs.Nodes[0].GetWorkload().GetName())
		assert.Empty(t, cmp.Diff([]*vulnerabilities.PackageTypeCount{
			{Value: "apk", Count: 1},
			{Value: "gem", Count: 1},
			{Value: "maven", Count: 1},
			{Value: "npm", Count: 3},
			{Value: "npm-extra", Count: 1},
			{Value: "npm2", Count: 1},
		}, jobs.GetPackageTypeCounts(), protocmp.Transform()))
	})

	t.Run("finding counts match the image contract including aliases and suppressions", func(t *testing.T) {
		image, err := client.ListVulnerabilitiesForImage(ctx, "mixed-a", "v1", vulnerabilities.IncludeSuppressed())
		require.NoError(t, err)
		workloads, err := client.ListVulnerabilitySummaries(ctx, append(options, vulnerabilities.WorkloadFilter("app-a"))...)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(image.GetPackageTypeCounts(), workloads.GetPackageTypeCounts(), protocmp.Transform()))
	})

	t.Run("pagination and sorting use matching workloads but choices stay complete", func(t *testing.T) {
		pageOptions := append(options,
			vulnerabilities.PackageTypeFilter("npm"),
			vulnerabilities.SbomStatusFilter(vulnerabilities.SbomStatus_SBOM_STATUS_READY),
			vulnerabilities.Order(vulnerabilities.OrderByRiskScore, vulnerabilities.Direction_DESC),
			vulnerabilities.Limit(1))
		for repeat := 0; repeat < 2; repeat++ {
			names := []string{}
			for offset := int32(0); offset < 3; offset++ {
				response, err := client.ListVulnerabilitySummaries(ctx, append(pageOptions, vulnerabilities.Offset(offset))...)
				require.NoError(t, err)
				require.Len(t, response.GetNodes(), 1)
				assert.Equal(t, int64(3), response.GetPageInfo().GetTotalCount())
				assert.Equal(t, offset < 2, response.GetPageInfo().GetHasNextPage())
				assert.Empty(t, cmp.Diff(types, response.GetPackageTypeCounts(), protocmp.Transform()))
				names = append(names, response.Nodes[0].GetWorkload().GetName())
			}
			assert.Equal(t, []string{"app-a", "job-a", "app-b"}, names)
		}
		for _, tc := range []struct {
			name   string
			filter vulnerabilities.Option
			total  int64
			nodes  int
		}{
			{"empty page", vulnerabilities.Offset(50), 3, 0},
			{"default limit", vulnerabilities.Limit(0), 3, 3},
			{"priority", vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_ELEVATED), 0, 0},
			{"KEV", vulnerabilities.KevFilter(false), 1, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				response, err := client.ListVulnerabilitySummaries(ctx, append(pageOptions, tc.filter)...)
				require.NoError(t, err)
				assert.Equal(t, tc.total, response.GetPageInfo().GetTotalCount())
				assert.Len(t, response.GetNodes(), tc.nodes)
				assert.Empty(t, cmp.Diff(types, response.GetPackageTypeCounts(), protocmp.Transform()))
			})
		}
	})

	t.Run("single bulk and coverage remain unaffected by the list option", func(t *testing.T) {
		aggregate, err := client.GetVulnerabilitySummary(ctx, options...)
		require.NoError(t, err)
		withOption, err := client.GetVulnerabilitySummary(ctx, append(options, vulnerabilities.PackageTypeFilter("unknown"))...)
		require.NoError(t, err)
		assert.True(t, proto.Equal(aggregate, withOption))
		assert.Equal(t, int32(8), aggregate.GetWorkloadCount())
		assert.Equal(t, int32(5), aggregate.GetSbomCount())
		assert.Equal(t, float32(62.5), aggregate.GetCoverage())
		bulk, err := client.GetVulnerabilitySummaries(ctx, []string{"packages", "empty"},
			vulnerabilities.ClusterFilter("dev"), vulnerabilities.PackageTypeFilter("unknown"))
		require.NoError(t, err)
		assert.True(t, proto.Equal(aggregate, bulk.GetSummaries()["packages"]))
		assert.Zero(t, bulk.GetSummaries()["empty"].GetWorkloadCount())
	})

	t.Run("membership ignores findings on a previous image tag", func(t *testing.T) {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: "mixed-a", Tag: "v2"}))
		_, err := pool.Exec(ctx, `UPDATE workloads SET image_tag = 'v2', state = 'processing' WHERE name = 'app-a'`)
		require.NoError(t, err)
		unfiltered, err := client.ListVulnerabilitySummaries(ctx, append(options, vulnerabilities.WorkloadFilter("app-a"))...)
		require.NoError(t, err)
		require.Len(t, unfiltered.GetNodes(), 1)
		assert.Equal(t, "v1", unfiltered.Nodes[0].GetVulnerabilitySummary().GetStaleImageTag())
		assert.Equal(t, int32(8), unfiltered.Nodes[0].GetVulnerabilitySummary().GetTotal())
		assert.Empty(t, unfiltered.GetPackageTypeCounts())
		filtered, err := client.ListVulnerabilitySummaries(ctx, append(options,
			vulnerabilities.WorkloadFilter("app-a"), vulnerabilities.PackageTypeFilter("npm"))...)
		require.NoError(t, err)
		assert.Empty(t, filtered.GetNodes())
		assert.Empty(t, filtered.GetPackageTypeCounts())
	})
}
