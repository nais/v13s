//go:build integration_test

package grpcvulnerabilities_test

import (
	"cmp"
	"slices"
	"strconv"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type cveImpactImage struct {
	name     string
	tag      string
	packages []string
}

type cveImpactWorkload struct {
	name    string
	kind    string
	team    string
	cluster string
	image   string
	tag     string
}

type cveImpactCase struct {
	name    string
	id      string
	options []vulnerabilities.Option
	want    *vulnerabilities.CveImpact
}

type cveWorkloadOrder struct {
	field vulnerabilities.OrderByField
	key   func(*vulnerabilities.WorkloadForVulnerability) string
}

var cveWorkloadOrders = []cveWorkloadOrder{
	{vulnerabilities.OrderByWorkload, func(n *vulnerabilities.WorkloadForVulnerability) string { return n.GetWorkloadRef().GetName() }},
	{vulnerabilities.OrderByImage, func(n *vulnerabilities.WorkloadForVulnerability) string {
		return n.GetWorkloadRef().GetImageName() + "\x00" + n.GetWorkloadRef().GetImageTag()
	}},
	{vulnerabilities.OrderByPackage, func(n *vulnerabilities.WorkloadForVulnerability) string { return n.GetVulnerability().GetPackage() }},
	{vulnerabilities.OrderByNamespace, func(n *vulnerabilities.WorkloadForVulnerability) string { return n.GetWorkloadRef().GetNamespace() }},
	{vulnerabilities.OrderByCluster, func(n *vulnerabilities.WorkloadForVulnerability) string { return n.GetWorkloadRef().GetCluster() }},
	{vulnerabilities.OrderBySuppressed, func(n *vulnerabilities.WorkloadForVulnerability) string {
		return strconv.FormatBool(n.GetVulnerability().GetSuppression().GetSuppressed())
	}},
}

func TestServer_CveImpactAndOrdering(t *testing.T) {
	ctx, db, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()

	const cveID = "CVE-IMPACT-1"
	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: cveID, Severity: int32(vulnerabilities.Severity_HIGH), Refs: map[string]string{}},
		{CveID: "GHSA-impact", Severity: int32(vulnerabilities.Severity_HIGH), Refs: map[string]string{}},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })
	db.BatchUpsertCveAlias(ctx, []sql.BatchUpsertCveAliasParams{
		{Alias: "GHSA-impact", CanonicalCveID: cveID},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })

	for _, image := range []cveImpactImage{
		{"shared", "v1", []string{"pkg-a", "pkg-b"}},
		{"shared", "v2", []string{"pkg-a"}},
		{"other", "v1", []string{"pkg-c"}},
		{"failed", "v1", []string{"pkg-inactive"}},
	} {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image.name, Tag: image.tag, Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = 'updated' WHERE name = $1 AND tag = $2`, image.name, image.tag)
		require.NoError(t, err)
		for _, pkg := range image.packages {
			db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
				{ImageName: image.name, ImageTag: image.tag, Package: pkg, CveID: cveID, Source: "test"},
			}).Exec(func(_ int, err error) { require.NoError(t, err) })
		}
	}
	db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		{ImageName: "shared", ImageTag: "v1", Package: "pkg-a", CveID: "GHSA-impact", Source: "test"},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })
	for _, wl := range []cveImpactWorkload{
		{name: "b-app", kind: "app", team: "team-a", cluster: "dev", image: "shared", tag: "v1"},
		{name: "a-app", kind: "app", team: "team-a", cluster: "dev", image: "shared", tag: "v1"},
		{name: "c-job", kind: "job", team: "team-a", cluster: "prod", image: "shared", tag: "v2"},
		{name: "d-app", kind: "app", team: "team-b", cluster: "dev", image: "other", tag: "v1"},
		{name: "failed", kind: "app", team: "team-b", cluster: "dev", image: "failed", tag: "v1"},
	} {
		id, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: wl.name, WorkloadType: wl.kind, Namespace: wl.team, Cluster: wl.cluster,
			ImageName: wl.image, ImageTag: wl.tag,
		})
		require.NoError(t, err)
		require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{ID: id, State: sql.WorkloadStateUpdated}))
	}
	_, err := pool.Exec(ctx, `UPDATE images SET state = 'failed' WHERE name = 'failed'`)
	require.NoError(t, err)
	require.NoError(t, db.SuppressVulnerability(ctx, sql.SuppressVulnerabilityParams{
		ImageName: "shared", Package: "pkg-b", CveID: cveID, Suppressed: true,
		SuppressedBy: "test", Reason: sql.VulnerabilitySuppressReasonFalsePositive, ReasonText: "test",
	}))

	for _, tc := range []cveImpactCase{
		{"all findings", cveID, []vulnerabilities.Option{vulnerabilities.IncludeSuppressed()}, &vulnerabilities.CveImpact{WorkloadCount: 4, ImageCount: 3, PackageCount: 3}},
		{"alias", "GHSA-impact", []vulnerabilities.Option{vulnerabilities.IncludeSuppressed()}, &vulnerabilities.CveImpact{WorkloadCount: 4, ImageCount: 3, PackageCount: 3}},
		{"unsuppressed", cveID, nil, &vulnerabilities.CveImpact{WorkloadCount: 4, ImageCount: 3, PackageCount: 2}},
		{"team", cveID, []vulnerabilities.Option{vulnerabilities.NamespaceFilter("team-a"), vulnerabilities.IncludeSuppressed()}, &vulnerabilities.CveImpact{WorkloadCount: 3, ImageCount: 2, PackageCount: 2}},
		{"excluded team", cveID, []vulnerabilities.Option{vulnerabilities.ExcludeNamespacesFilter("team-a")}, &vulnerabilities.CveImpact{WorkloadCount: 1, ImageCount: 1, PackageCount: 1}},
		{"cluster", cveID, []vulnerabilities.Option{vulnerabilities.ClusterFilter("prod")}, &vulnerabilities.CveImpact{WorkloadCount: 1, ImageCount: 1, PackageCount: 1}},
		{"image", cveID, []vulnerabilities.Option{vulnerabilities.ImageFilter("shared", "v2")}, &vulnerabilities.CveImpact{WorkloadCount: 1, ImageCount: 1, PackageCount: 1}},
		{"no matches", cveID, []vulnerabilities.Option{vulnerabilities.NamespaceFilter("missing")}, &vulnerabilities.CveImpact{}},
		{"page past the end", cveID, []vulnerabilities.Option{vulnerabilities.Offset(100), vulnerabilities.IncludeSuppressed()}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{tc.id}},
				append(tc.options, vulnerabilities.Limit(1))...)
			require.NoError(t, err)
			assert.True(t, proto.Equal(tc.want, resp.GetImpact()), "want %v, got %v", tc.want, resp.GetImpact())
		})
	}

	t.Run("workload count matches the CVE list", func(t *testing.T) {
		require.NoError(t, db.RefreshCveWorkloadCounts(ctx))
		opts := []vulnerabilities.Option{vulnerabilities.IncludeSuppressed(), vulnerabilities.ExcludeNamespacesFilter("team-b")}
		summaries, err := client.ListCveSummaries(ctx, append(opts, vulnerabilities.Limit(10))...)
		require.NoError(t, err)
		idx := slices.IndexFunc(summaries.GetNodes(), func(n *vulnerabilities.CveSummary) bool { return n.GetCve().GetId() == cveID })
		require.NotEqual(t, -1, idx)
		resp, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{cveID}}, opts...)
		require.NoError(t, err)
		assert.Equal(t, summaries.GetNodes()[idx].GetAffectedWorkloads(), resp.GetImpact().GetWorkloadCount())
	})

	for _, order := range cveWorkloadOrders {
		for _, direction := range []vulnerabilities.Direction{vulnerabilities.Direction_ASC, vulnerabilities.Direction_DESC} {
			t.Run(order.field.String()+direction.String(), func(t *testing.T) {
				resp, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{cveID}},
					vulnerabilities.IncludeSuppressed(), vulnerabilities.Order(order.field, direction))
				require.NoError(t, err)
				require.Len(t, resp.Nodes, 6)
				assert.True(t, slices.IsSortedFunc(resp.Nodes, func(a, b *vulnerabilities.WorkloadForVulnerability) int {
					result := cmp.Compare(order.key(a), order.key(b))
					if direction == vulnerabilities.Direction_DESC {
						return -result
					}
					return result
				}))
				for offset, expected := range resp.Nodes {
					page, err := client.ListWorkloadsForVulnerability(ctx, vulnerabilities.VulnerabilityFilter{CveIds: []string{cveID}},
						vulnerabilities.IncludeSuppressed(), vulnerabilities.Order(order.field, direction),
						vulnerabilities.Limit(1), vulnerabilities.Offset(int32(offset)))
					require.NoError(t, err)
					require.Len(t, page.Nodes, 1)
					assert.Equal(t, expected.GetWorkloadRef(), page.Nodes[0].GetWorkloadRef())
					assert.Equal(t, expected.GetVulnerability().GetId(), page.Nodes[0].GetVulnerability().GetId())
				}
			})
		}
	}
}

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
