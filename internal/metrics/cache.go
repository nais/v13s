package metrics

import "sync"

type MetricCache struct {
	m sync.Map
}

func NewWorkloadMetricCache() *MetricCache {
	return &MetricCache{}
}

func (m *MetricCache) Set(key string, val CachedMetrics) {
	m.m.Store(key, val)
}

func (m *MetricCache) Range(f func(key, value any) bool) {
	m.m.Range(f)
}

func (c *MetricCache) Reset() {
	c.Range(func(key, _ any) bool {
		c.m.Delete(key)
		return true
	})
}

type CachedMetrics struct {
	Cluster, Namespace, Name string
	RiskScore                int32
	Vulns                    map[string]int32
}
