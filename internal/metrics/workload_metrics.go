package metrics

import (
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources/source"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	Namespace = "v13s"
)

var labels = []string{"workload_cluster", "workload_namespace", "workload_name", "workload_type"}

var WorkloadRiskScore = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "workload_risk_score",
		Help:      "Aggregated risk score of a workload, based on vulnerabilities, CVSS, and inherited risk. Higher values indicate higher risk.",
	},
	labels,
)

var WorkloadVulnerabilities = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "workload_vulnerabilities",
		Help:      "Number of vulnerabilities detected in the workload, grouped by severity.",
	},
	append(labels, "severity"),
)

func Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		WorkloadRiskScore,
		WorkloadVulnerabilities,
	}
}

func SetWorkloadMetrics(workloads []*sql.ListWorkloadsByImageRow, summary *source.VulnerabilitySummary) {
	for _, w := range workloads {
		labelValues := []string{w.Cluster, w.Namespace, w.Name, w.WorkloadType}
		WorkloadRiskScore.WithLabelValues(labelValues...).Set(float64(summary.RiskScore))
		WorkloadVulnerabilities.WithLabelValues(append(labelValues, "CRITICAL")...).Set(float64(summary.Critical))
		WorkloadVulnerabilities.WithLabelValues(append(labelValues, "HIGH")...).Set(float64(summary.High))
		WorkloadVulnerabilities.WithLabelValues(append(labelValues, "MEDIUM")...).Set(float64(summary.Medium))
		WorkloadVulnerabilities.WithLabelValues(append(labelValues, "LOW")...).Set(float64(summary.Low))
		WorkloadVulnerabilities.WithLabelValues(append(labelValues, "UNASSIGNED")...).Set(float64(summary.Unassigned))
	}
}
