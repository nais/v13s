package config

import (
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

func TestExplanationConfig(t *testing.T) {
	var cfg Config
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("AUTHORIZED_SERVICE_ACCOUNTS", "test")
	require.NoError(t, envconfig.Process("", &cfg))
	require.False(t, cfg.Updater.ExplainCvesEnabled)
	require.False(t, cfg.Explanation.Visible)
	require.NoError(t, cfg.Explanation.Validate(false))
	require.Error(t, cfg.Explanation.Validate(true))

	valid := ExplanationConfig{Project: "test-project", Region: "europe-north1", Model: "gemini-test", MaxPerRun: 200, Concurrency: 2, MaxOutputTokens: 400}
	require.NoError(t, valid.Validate(true))
	for name, change := range map[string]func(*ExplanationConfig){
		"global":       func(c *ExplanationConfig) { c.Region = "global" },
		"US":           func(c *ExplanationConfig) { c.Region = "us-central1" },
		"UK":           func(c *ExplanationConfig) { c.Region = "europe-west2" },
		"Swiss":        func(c *ExplanationConfig) { c.Region = "europe-west6" },
		"model path":   func(c *ExplanationConfig) { c.Model = "projects/other/models/gemini-test" },
		"zero calls":   func(c *ExplanationConfig) { c.MaxPerRun = 0 },
		"zero workers": func(c *ExplanationConfig) { c.Concurrency = 0 },
		"tokens":       func(c *ExplanationConfig) { c.MaxOutputTokens = 2001 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			change(&cfg)
			require.Error(t, cfg.Validate(true))
		})
	}
}
