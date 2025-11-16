package metrics

import (
	"context"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	Namespace = "v13s"
)

//var (
//labels = []string{"workload_cluster", "workload_namespace", "workload_name"}
//
//WorkloadRiskScore = prometheus.NewGaugeVec(
//prometheus.GaugeOpts{
//Namespace: Namespace,
//Name:      "workload_risk_score",
//Help:      "Aggregated risk score of a workload, based on vulnerabilities, CVSS, and inherited risk. Higher values indicate higher risk.",
//},
//labels,
//)
//
//WorkloadVulnerabilities = prometheus.NewGaugeVec(
//prometheus.GaugeOpts{
//Namespace: Namespace,
//Name:      "workload_vulnerabilities",
//Help:      "Number of vulnerabilities detected in the workload, grouped by severity.",
//},
//append(labels, "severity"),
//)
//)
//
//func Collectors() []prometheus.Collector {
//return []prometheus.Collector{
//WorkloadRiskScore,
//WorkloadVulnerabilities,
//}
//}

//unc SetWorkloadMetrics(w *sql.ListWorkloadsByImageRow, summary *sources.VulnerabilitySummary) {
//	labelValues := []string{w.Cluster, w.Namespace, w.Name}
//	WorkloadRiskScore.WithLabelValues(labelValues...).Set(float64(summary.RiskScore))
//	WorkloadVulnerabilities.WithLabelValues(append(labelValues, "CRITICAL")...).Set(float64(summary.Critical))
//	WorkloadVulnerabilities.WithLabelValues(append(labelValues, "HIGH")...).Set(float64(summary.High))
//	WorkloadVulnerabilities.WithLabelValues(append(labelValues, "MEDIUM")...).Set(float64(summary.Medium))
//	WorkloadVulnerabilities.WithLabelValues(append(labelValues, "LOW")...).Set(float64(summary.Low))
//	WorkloadVulnerabilities.WithLabelValues(append(labelValues, "UNASSIGNED")...).Set(float64(summary.Unassigned))
// }

var (
	meter metric.Meter

	workloadRiskScore       metric.Float64ObservableGauge
	workloadVulnerabilities metric.Int64ObservableGauge

	workloadMetricCache = NewWorkloadMetricCache()
)

func InitOTelMetrics(m metric.Meter) error {
	meter = m

	var err error

	workloadRiskScore, err = meter.Float64ObservableGauge(
		"v13s_workload_risk_score",
		metric.WithDescription("Aggregated workload risk score based on vulnerabilities."),
	)
	if err != nil {
		return err
	}

	workloadVulnerabilities, err = meter.Int64ObservableGauge(
		"v13s_workload_vulnerabilities",
		metric.WithDescription("Number of vulnerabilities per workload by severity."),
	)
	if err != nil {
		return err
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			workloadMetricCache.Range(func(_, v any) bool {
				wm := v.(CachedMetrics)

				attrs := []attribute.KeyValue{
					attribute.String("workload_cluster", wm.Cluster),
					attribute.String("workload_namespace", wm.Namespace),
					attribute.String("workload_name", wm.Name),
				}

				o.ObserveFloat64(
					workloadRiskScore,
					float64(wm.RiskScore),
					metric.WithAttributes(attrs...),
				)

				for sev, val := range wm.Vulns {
					o.ObserveInt64(
						workloadVulnerabilities,
						int64(val),
						metric.WithAttributes(
							append(attrs, attribute.String("severity", sev))...,
						),
					)
				}

				return true
			})
			return nil
		},
		workloadRiskScore,
		workloadVulnerabilities,
	)

	return err
}

func SetWorkloadMetrics(w *sql.ListWorkloadsByImageRow, summary *sources.VulnerabilitySummary) {
	key := w.Cluster + "/" + w.Namespace + "/" + w.Name

	workloadMetricCache.Set(key, CachedMetrics{
		Cluster:   w.Cluster,
		Namespace: w.Namespace,
		Name:      w.Name,
		RiskScore: summary.RiskScore,
		Vulns: map[string]int32{
			"CRITICAL":   summary.Critical,
			"HIGH":       summary.High,
			"MEDIUM":     summary.Medium,
			"LOW":        summary.Low,
			"UNASSIGNED": summary.Unassigned,
		},
	})
}
