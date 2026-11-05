package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabasePoolConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  map[string]string
		want DatabasePoolConfig
	}{
		{
			name: "defaults",
			want: DatabasePoolConfig{MainMaxConnections: 8, JobMaxConnections: 12, RiverUIMaxConnections: 2},
		},
		{
			name: "independent overrides",
			env: map[string]string{
				"DATABASE_MAX_CONNECTIONS":          "24",
				"JOB_DATABASE_MAX_CONNECTIONS":      "40",
				"RIVER_UI_DATABASE_MAX_CONNECTIONS": "3",
			},
			want: DatabasePoolConfig{MainMaxConnections: 24, JobMaxConnections: 40, RiverUIMaxConnections: 3},
		},
		{
			name: "minimum pool sizes",
			env: map[string]string{
				"DATABASE_MAX_CONNECTIONS":          "2",
				"JOB_DATABASE_MAX_CONNECTIONS":      "1",
				"RIVER_UI_DATABASE_MAX_CONNECTIONS": "1",
			},
			want: DatabasePoolConfig{MainMaxConnections: 2, JobMaxConnections: 1, RiverUIMaxConnections: 1},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setDatabasePoolEnv(t)
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			cfg, err := NewConfig()
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.DatabasePools)
		})
	}
}

func TestDatabasePoolConfigRejectsSingleMainConnection(t *testing.T) {
	setDatabasePoolEnv(t)
	t.Setenv("DATABASE_MAX_CONNECTIONS", "1")
	cfg, err := NewConfig()
	require.ErrorContains(t, err, "DATABASE_MAX_CONNECTIONS must be at least 2")
	require.Nil(t, cfg)
}

func TestDatabasePoolConfigRejectsInvalidLimits(t *testing.T) {
	for _, key := range []string{
		"DATABASE_MAX_CONNECTIONS",
		"JOB_DATABASE_MAX_CONNECTIONS",
		"RIVER_UI_DATABASE_MAX_CONNECTIONS",
	} {
		for _, value := range []string{"0", "-1", "2147483648", "invalid"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				setDatabasePoolEnv(t)
				t.Setenv(key, value)
				cfg, err := NewConfig()
				require.ErrorContains(t, err, key)
				require.Nil(t, cfg)
			})
		}
	}
}

func setDatabasePoolEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "host=localhost dbname=test")
	t.Setenv("AUTHORIZED_SERVICE_ACCOUNTS", "test")
	for _, key := range []string{
		"DATABASE_MAX_CONNECTIONS",
		"JOB_DATABASE_MAX_CONNECTIONS",
		"RIVER_UI_DATABASE_MAX_CONNECTIONS",
	} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}
	t.Setenv("KEV_VULNCHECK_ENABLED", "false")
}
