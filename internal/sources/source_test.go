package sources

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDependencyTrackSourcesConfig(t *testing.T) {
	config, err := parseDependencyTrackSourcesConfig(`{
  "active": {"type":"dependencytrack","url":"https://active.example","username":"v13s","password":"active-secret","instance":"dependencytrack"},
  "warmup": [{"type":"dependencytrack","url":"https://warmup.example","username":"v13s","password":"warmup-secret","instance":"warmup"}]
}`)
	require.NoError(t, err)
	require.Equal(t, DependencyTrackConfig{
		Type:     DependencytrackSourceName,
		Url:      "https://active.example",
		Username: "v13s",
		Password: "active-secret",
		Instance: "dependencytrack",
	}, config.Active)
	require.Equal(t, []DependencyTrackConfig{{
		Type:     DependencytrackSourceName,
		Url:      "https://warmup.example",
		Username: "v13s",
		Password: "warmup-secret",
		Instance: "warmup",
	}}, config.Warmup)
}

func TestParseDependencyTrackSourcesConfigRequiresActiveSource(t *testing.T) {
	_, err := parseDependencyTrackSourcesConfig(`{"warmup":[]}`)
	require.ErrorContains(t, err, "active.type")
}

func TestSourcesUploadInstancesIncludesActiveAndWarmup(t *testing.T) {
	active := &testSource{identity: Identity{Type: DependencytrackSourceName, Instance: "active"}}
	warmup := &testSource{identity: Identity{Type: DependencytrackSourceName, Instance: "warmup"}}
	sources, err := NewSet(active, warmup)
	require.NoError(t, err)
	require.Equal(t, []string{"active", "warmup"}, sources.UploadInstances())
}

type testSource struct {
	identity Identity
}

func (s *testSource) Name() string                                 { return s.identity.Type }
func (s *testSource) Identity() Identity                           { return s.identity }
func (s *testSource) Delete(context.Context, string, string) error { return nil }
func (s *testSource) GetVulnerabilities(context.Context, string, string, bool) ([]*Vulnerability, error) {
	return nil, nil
}
func (s *testSource) GetVulnerabilitySummary(context.Context, string, string) (*VulnerabilitySummary, error) {
	return nil, nil
}
func (s *testSource) IsTaskInProgress(context.Context, string) (bool, error) { return false, nil }
func (s *testSource) MaintainSuppressedVulnerabilities(context.Context, []*SuppressedVulnerability) error {
	return nil
}
func (s *testSource) ProjectExists(context.Context, string, string) (bool, error) { return false, nil }
func (s *testSource) UploadAttestation(context.Context, string, string, []byte) (*UploadAttestationResponse, error) {
	return nil, nil
}

func TestParseDependencyTrackSourcesConfigRejectsIncompleteWarmupSource(t *testing.T) {
	_, err := parseDependencyTrackSourcesConfig(`{
  "active": {"type":"dependencytrack","instance":"active","url":"https://active.example","username":"v13s","password":"secret"},
  "warmup": [{"type":"dependencytrack","instance":"warmup","url":"https://warmup.example","username":"","password":"secret"}]
}`)
	require.ErrorContains(t, err, "warmup[0].username")
}
