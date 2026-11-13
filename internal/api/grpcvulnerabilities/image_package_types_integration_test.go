//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"
	"time"

	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_ImagePackageTypes(t *testing.T) {
	ctx, _, pool, client, cleanup := setupTest(t, testSetupConfig{}, true)
	defer cleanup()
	_, err := pool.Exec(ctx, `
		INSERT INTO images (name, tag, state) VALUES
			('packages', 'current', 'updated'), ('packages', 'old', 'updated'),
			('clean', 'current', 'updated'), ('other', 'current', 'updated');
		INSERT INTO cve (cve_id, cve_title, cve_desc, cve_link, severity, refs)
			VALUES ('CVE-packages', '', '', '', 1, '{}'), ('GHSA-alias', '', '', '', 4, '{}');
		INSERT INTO cve_alias (alias, canonical_cve_id) VALUES ('GHSA-alias', 'CVE-packages');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version) VALUES
			('packages', 'current', 'pkg:npm/@scope/library@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:npm/@scope/library@1', 'GHSA-alias', 'test', ''),
			('packages', 'current', 'pkg:npm/another@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:npm2/library@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:gem/hidden@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:NPM/invalid@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'not-a-purl', 'CVE-packages', 'test', ''),
			('packages', 'old', 'pkg:cargo/old@1', 'CVE-packages', 'test', ''),
			('other', 'current', 'pkg:pypi/other@1', 'CVE-packages', 'test', '');
		INSERT INTO suppressed_vulnerabilities (image_name, package, cve_id, suppressed)
			VALUES ('packages', 'pkg:gem/hidden@1', 'CVE-packages', TRUE);
		UPDATE vulnerabilities SET severity_since = '2026-01-01' WHERE image_name = 'packages';
		UPDATE vulnerabilities SET severity_since = '2026-02-01'
			WHERE image_name = 'packages' AND package = 'pkg:npm/another@1';
	`)
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		options []vulnerabilities.Option
		want    map[string]int64
	}{
		{"first page", []vulnerabilities.Option{vulnerabilities.Limit(1)}, map[string]int64{"npm": 2, "npm2": 1}},
		{"exhausted page", []vulnerabilities.Option{vulnerabilities.Limit(1), vulnerabilities.Offset(100)}, map[string]int64{"npm": 2, "npm2": 1}},
		{"suppressed", []vulnerabilities.Option{vulnerabilities.IncludeSuppressed()}, map[string]int64{"gem": 1, "npm": 2, "npm2": 1}},
		{"package", []vulnerabilities.Option{vulnerabilities.PackageTypeFilter("npm")}, map[string]int64{"npm": 2}},
		{"no package", []vulnerabilities.Option{vulnerabilities.PackageTypeFilter("unknown")}, map[string]int64{}},
		{"severity", []vulnerabilities.Option{vulnerabilities.SeverityFilter(vulnerabilities.Severity_HIGH)}, map[string]int64{"npm": 2, "npm2": 1}},
		{"no severity", []vulnerabilities.Option{vulnerabilities.SeverityFilter(vulnerabilities.Severity_CRITICAL)}, map[string]int64{}},
		{"no priority", []vulnerabilities.Option{vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_ELEVATED)}, map[string]int64{}},
		{"no kev", []vulnerabilities.Option{vulnerabilities.KevFilter(true)}, map[string]int64{}},
		{"since", []vulnerabilities.Option{vulnerabilities.Since(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))}, map[string]int64{"npm": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := client.ListVulnerabilitiesForImage(ctx, "packages", "current", tc.options...)
			require.NoError(t, err)
			got := map[string]int64{}
			for _, facet := range response.GetPackageTypeFacets() {
				got[facet.GetValue()] = facet.GetCount()
			}
			assert.Equal(t, tc.want, got)
		})
	}
	response, err := client.ListVulnerabilitiesForImage(ctx, "packages", "old")
	require.NoError(t, err)
	require.Len(t, response.GetPackageTypeFacets(), 1)
	assert.Equal(t, "cargo", response.PackageTypeFacets[0].GetValue())
	assert.Equal(t, int64(1), response.PackageTypeFacets[0].GetCount())
	response, err = client.ListVulnerabilitiesForImage(ctx, "clean", "current")
	require.NoError(t, err)
	assert.Empty(t, response.GetPackageTypeFacets())
}
