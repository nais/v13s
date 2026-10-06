//go:build integration_test

package kev_test

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/kev"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetcher_Sync_RecalculatesStoredSummaries(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	db := sql.New(pool)

	const cveID = "CVE-2026-48710"
	const aliasID = "GHSA-2026-48710"
	for _, image := range []string{"image-used", "image-alias", "image-unused"} {
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: image, Tag: "v1", Metadata: map[string]string{}}))
	}
	for _, image := range []string{"image-used", "image-alias"} {
		_, err := db.UpsertWorkload(ctx, sql.UpsertWorkloadParams{
			Name: image, WorkloadType: "app", Namespace: "namespace", Cluster: "cluster", ImageName: image, ImageTag: "v1",
		})
		require.NoError(t, err)
	}

	db.BatchUpsertCve(ctx, []sql.BatchUpsertCveParams{
		{CveID: cveID, CveTitle: cveID, CveDesc: "desc", CveLink: "link", Severity: 1, Refs: map[string]string{}},
		{CveID: aliasID, CveTitle: aliasID, CveDesc: "desc", CveLink: "link", Severity: 1, Refs: map[string]string{}},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })
	db.BatchUpsertCveAlias(ctx, []sql.BatchUpsertCveAliasParams{{Alias: aliasID, CanonicalCveID: cveID}}).
		Exec(func(_ int, err error) { require.NoError(t, err) })
	db.BatchUpsertVulnerabilities(ctx, []sql.BatchUpsertVulnerabilitiesParams{
		{ImageName: "image-used", ImageTag: "v1", Package: "pkg:pypi/starlette@0.49.3", CveID: cveID, Source: "test"},
		{ImageName: "image-alias", ImageTag: "v1", Package: "pkg:pypi/starlette@0.49.3", CveID: aliasID, Source: "test"},
		{ImageName: "image-unused", ImageTag: "v1", Package: "pkg:pypi/starlette@0.49.3", CveID: cveID, Source: "test"},
	}).Exec(func(_ int, err error) { require.NoError(t, err) })
	for _, image := range []string{"image-used", "image-alias", "image-unused"} {
		require.NoError(t, db.RecalculateVulnerabilitySummary(ctx, sql.RecalculateVulnerabilitySummaryParams{ImageName: image, ImageTag: "v1"}))
	}

	type counts struct{ kev, ransomware, highRisk, monitor int32 }
	summary := func(image string) counts {
		var c counts
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT kev_count, ransomware_count, high_risk, monitor FROM vulnerability_summary WHERE image_name = $1 AND image_tag = 'v1'`,
			image).Scan(&c.kev, &c.ransomware, &c.highRisk, &c.monitor))
		return c
	}
	require.Equal(t, counts{monitor: 1}, summary("image-used"))

	source := staticSource{name: kev.SourceVulnCheck, assertions: []kev.Assertion{{CveID: cveID, KnownRansomware: true}}}
	require.NoError(t, kev.NewFetcher(pool, testLogger(), source).Sync(ctx))

	assert.Equal(t, counts{kev: 1, ransomware: 1, highRisk: 1}, summary("image-used"), "summary of an image in use is recalculated")
	assert.Equal(t, counts{kev: 1, ransomware: 1, highRisk: 1}, summary("image-alias"), "summary of an image referencing the CVE through an alias is recalculated")
	assert.Equal(t, counts{monitor: 1}, summary("image-unused"), "summaries of images without workloads are left as is")
}
