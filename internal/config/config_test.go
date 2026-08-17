package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourcesValueUsesConfiguredSources(t *testing.T) {
	config := Config{Sources: `{"active":{"type":"dependencytrack","instance":"active","url":"https://active.example","username":"v13s","password":"secret"}}`}

	value, err := config.SourcesValue()
	require.NoError(t, err)
	require.Equal(t, config.Sources, value)
}

func TestSourcesValueFallsBackToLegacyDependencyTrackConfig(t *testing.T) {
	config := Config{DependencyTrack: LegacyDependencyTrackConfig{
		Url:      "https://dependencytrack.example/api",
		Username: "v13s",
		Password: "secret",
	}}

	value, err := config.SourcesValue()
	require.NoError(t, err)
	require.JSONEq(t, `{"active":{"type":"dependencytrack","instance":"dependencytrack","url":"https://dependencytrack.example/api","username":"v13s","password":"secret"}}`, value)
}
