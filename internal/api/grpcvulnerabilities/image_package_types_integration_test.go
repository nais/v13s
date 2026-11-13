//go:build integration_test

package grpcvulnerabilities_test

import (
	"testing"

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
			VALUES ('CVE-packages', '', '', '', 1, '{}');
		INSERT INTO vulnerabilities (image_name, image_tag, package, cve_id, source, latest_version) VALUES
			('packages', 'current', 'pkg:npm/@scope/library@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:npm/another@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:npm2/library@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:gem/hidden@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'pkg:NPM/invalid@1', 'CVE-packages', 'test', ''),
			('packages', 'current', 'not-a-purl', 'CVE-packages', 'test', ''),
			('packages', 'old', 'pkg:cargo/old@1', 'CVE-packages', 'test', ''),
			('other', 'current', 'pkg:pypi/other@1', 'CVE-packages', 'test', '');
		INSERT INTO suppressed_vulnerabilities (image_name, package, cve_id, suppressed)
			VALUES ('packages', 'pkg:gem/hidden@1', 'CVE-packages', TRUE);
	`)
	require.NoError(t, err)
	for _, opts := range [][]vulnerabilities.Option{
		{vulnerabilities.Limit(1)},
		{vulnerabilities.Limit(1), vulnerabilities.Offset(100)},
		{vulnerabilities.PackageTypeFilter("unknown")},
		{vulnerabilities.PackageTypeFilter("npm"), vulnerabilities.PriorityFilter(vulnerabilities.Priority_PRIORITY_ELEVATED)},
		{vulnerabilities.KevFilter(true)},
	} {
		response, err := client.ListVulnerabilitiesForImage(ctx, "packages", "current", opts...)
		require.NoError(t, err)
		assert.Equal(t, []string{"gem", "npm", "npm2"}, response.GetPackageTypes())
	}
	response, err := client.ListVulnerabilitiesForImage(ctx, "packages", "old")
	require.NoError(t, err)
	assert.Equal(t, []string{"cargo"}, response.GetPackageTypes())
	response, err = client.ListVulnerabilitiesForImage(ctx, "clean", "current")
	require.NoError(t, err)
	assert.Empty(t, response.GetPackageTypes())
}
