package metrics

import (
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

var databaseMetrics = newDatabaseCollector()

type databaseCollector struct {
	mu    sync.RWMutex
	pools map[string]*pgxpool.Pool

	poolConnections     *prometheus.Desc
	poolMax             *prometheus.Desc
	poolAcquireDuration *prometheus.Desc
	poolAcquires        *prometheus.Desc
	poolCanceled        *prometheus.Desc
	poolEmptyAcquires   *prometheus.Desc
}

func newDatabaseCollector() *databaseCollector {
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(Namespace, Subsystem, name), help, labels, nil)
	}
	return &databaseCollector{
		pools:               make(map[string]*pgxpool.Pool),
		poolConnections:     desc("database_pool_connections", "Connections held by a pool, split by state.", "pool", "state"),
		poolMax:             desc("database_pool_max_connections", "Maximum connections allowed by a pool.", "pool"),
		poolAcquireDuration: desc("database_pool_acquire_duration_seconds_total", "Cumulative time spent in successful pool acquisitions.", "pool"),
		poolAcquires:        desc("database_pool_acquires_total", "Successful pool acquisitions.", "pool"),
		poolCanceled:        desc("database_pool_acquire_cancellations_total", "Pool acquisitions canceled by their context.", "pool"),
		poolEmptyAcquires:   desc("database_pool_empty_acquires_total", "Successful acquisitions that had to wait for a pool resource.", "pool"),
	}
}

func TrackDatabasePool(name string, pool *pgxpool.Pool) {
	databaseMetrics.mu.Lock()
	defer databaseMetrics.mu.Unlock()
	databaseMetrics.pools[name] = pool
}

func (c *databaseCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.poolConnections, c.poolMax, c.poolAcquireDuration, c.poolAcquires, c.poolCanceled, c.poolEmptyAcquires,
	} {
		ch <- desc
	}
}

func (c *databaseCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for name, pool := range c.pools {
		stat := pool.Stat()
		ch <- prometheus.MustNewConstMetric(c.poolConnections, prometheus.GaugeValue, float64(stat.AcquiredConns()), name, "acquired")
		ch <- prometheus.MustNewConstMetric(c.poolConnections, prometheus.GaugeValue, float64(stat.IdleConns()), name, "idle")
		ch <- prometheus.MustNewConstMetric(c.poolConnections, prometheus.GaugeValue, float64(stat.ConstructingConns()), name, "constructing")
		ch <- prometheus.MustNewConstMetric(c.poolMax, prometheus.GaugeValue, float64(stat.MaxConns()), name)
		ch <- prometheus.MustNewConstMetric(c.poolAcquireDuration, prometheus.CounterValue, stat.AcquireDuration().Seconds(), name)
		ch <- prometheus.MustNewConstMetric(c.poolAcquires, prometheus.CounterValue, float64(stat.AcquireCount()), name)
		ch <- prometheus.MustNewConstMetric(c.poolCanceled, prometheus.CounterValue, float64(stat.CanceledAcquireCount()), name)
		ch <- prometheus.MustNewConstMetric(c.poolEmptyAcquires, prometheus.CounterValue, float64(stat.EmptyAcquireCount()), name)
	}
}
