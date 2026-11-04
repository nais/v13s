package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePoolConfig(t *testing.T) {
	for _, maxConnections := range []int32{1, 8, 40} {
		t.Run(fmt.Sprint(maxConnections), func(t *testing.T) {
			config, err := ParsePoolConfig(
				"host=localhost dbname=test pool_max_conns=90 pool_min_conns=9 pool_min_idle_conns=8",
				maxConnections,
			)
			require.NoError(t, err)
			require.Equal(t, maxConnections, config.MaxConns)
			require.Equal(t, min(int32(9), maxConnections), config.MinConns)
			require.Equal(t, min(int32(8), maxConnections), config.MinIdleConns)
		})
	}
}

func TestNewPoolRejectsInvalidLimitsBeforeConnecting(t *testing.T) {
	for _, migrate := range []bool{false, true} {
		for _, maxConnections := range []int32{0, -1} {
			pool, err := NewPool(context.Background(), unreachableDSN, maxConnections, nil, migrate)
			require.ErrorContains(t, err, "maximum connections must be at least 1")
			require.Nil(t, pool)
		}
	}
}
