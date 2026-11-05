package metrics

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func gatheredMetrics(t *testing.T, collectors ...prometheus.Collector) map[string]*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(collectors...)
	families, err := reg.Gather()
	require.NoError(t, err)
	result := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		result[family.GetName()] = family
	}
	return result
}

func TestDatabasePoolMetricsDoNotOpenConnections(t *testing.T) {
	collector := newDatabaseCollector()
	var attempts atomic.Int64
	for name, limit := range map[string]int32{"main": 17, "river": 23, "river_ui": 5} {
		cfg, err := pgxpool.ParseConfig("host=127.0.0.1 port=1 user=metrics-test dbname=not-a-metric-label")
		require.NoError(t, err)
		cfg.MaxConns = limit
		cfg.BeforeConnect = func(context.Context, *pgx.ConnConfig) error {
			attempts.Add(1)
			return errors.New("metrics must not connect")
		}
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		require.NoError(t, err)
		defer pool.Close()
		collector.pools[name] = pool
	}
	families := gatheredMetrics(t, collector)
	require.Zero(t, attempts.Load())
	maxima := make(map[string]float64)
	for _, metric := range families["nais_v13s_database_pool_max_connections"].Metric {
		require.Len(t, metric.Label, 1)
		require.Equal(t, "pool", metric.Label[0].GetName())
		maxima[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
	}
	require.Equal(t, map[string]float64{"main": 17, "river": 23, "river_ui": 5}, maxima)
}
