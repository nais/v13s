package sources

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/nais/v13s/internal/sources/dependencytrack/client"
	"github.com/stretchr/testify/assert"
)

func TestParseFinding(t *testing.T) {
	b, err := os.ReadFile("testdata/finding.json")
	assert.NoError(t, err)
	var f client.Finding
	err = json.Unmarshal(b, &f)
	assert.NoError(t, err)
	v, err := parseFinding(f)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:pypi/cryptography@43.0.1", v.Package)
	assert.Equal(t, "GHSA-79v4-65xg-pq4g", v.Cve.Id)
	assert.Equal(t, SeverityLow, v.Cve.Severity)
	assert.Equal(t, "17170e88-cfcb-4900-b3fb-5b0be0a071a5", v.Metadata.(*dependencytrackVulnMetadata).projectId)
	assert.Equal(t, "5b009251-5efd-4703-8579-49af6cd3d0c6", v.Metadata.(*dependencytrackVulnMetadata).componentId)
	assert.Equal(t, "6fa86367-6014-427e-8300-69269c16025b", v.Metadata.(*dependencytrackVulnMetadata).vulnerabilityUuid)
	assert.Equal(t, fmt.Sprintf("https://github.com/advisories/%s", "GHSA-79v4-65xg-pq4g"), v.Cve.Link)
	assert.Equal(t, true, v.Suppressed)
	fmt.Printf("%+v\n", v.Cve)
	assert.Equal(t, "Vulnerable OpenSSL included in cryptography wheels", v.Cve.Title)
	assert.Equal(t, "a loooong description", v.Cve.Description)
	assert.Equal(t, "44.0.1", v.LatestVersion)
	assert.Equal(t, 1, len(v.Cve.References))
}
