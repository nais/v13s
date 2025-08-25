package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Namespace = "v13s"
)

var labels = []string{"workload_name", "workload_namespace", "workload_type"}

var WorkloadRiskScore = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "workload_risk_score",
		Help:      "Aggregated risk score of a workload, based on vulnerabilities, CVSS, and inherited risk. Higher values indicate higher risk.",
	},
	labels,
)

var WorkloadCriticalCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "workload_critical_count",
		Help:      "Number of critical vulnerabilities (severity=CRITICAL) detected in the workload.",
	},
	labels,
)

// Collectors returns all custom prometheus collectors
func Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		WorkloadRiskScore,
		WorkloadCriticalCount,
	}
}
