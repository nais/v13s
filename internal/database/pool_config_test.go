package database

import (
	"context"
	"fmt"
	"testing"

	logrustest "github.com/sirupsen/logrus/hooks/test"
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	log, _ := logrustest.NewNullLogger()
	for _, migrate := range []bool{false, true} {
		for _, maxConnections := range []int32{0, -1, 1} {
			pool, err := NewPool(ctx, unreachableDSN, maxConnections, log, migrate)
			require.ErrorContains(t, err, "main database pool maximum connections must be at least 2")
			require.Nil(t, pool)
		}
	}
}
