package sources

import (
	"github.com/nais/dependencytrack/pkg/dependencytrack"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMetadataTypeAssertion(t *testing.T) {
	v := &Vulnerability{
		Metadata: &dependencytrack.VulnMetadata{
			ProjectId:         "123",
			ComponentId:       "456",
			VulnerabilityUuid: "789",
		},
	}
	meta, ok := v.Metadata.(*dependencytrack.VulnMetadata)
	require.True(t, ok)
	require.Equal(t, "123", meta.ProjectId)
	require.Equal(t, "456", meta.ComponentId)
	require.Equal(t, "789", meta.VulnerabilityUuid)
}
