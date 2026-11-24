package metrics

import "github.com/prometheus/client_golang/prometheus"

var SuppressionForwards = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "suppression_forwards_total",
		Help:      "Number of suppression changes forwarded to v0s by outcome.",
	},
	[]string{"outcome"},
)

func RecordSuppressionForwardOutcome(outcome string) {
	SuppressionForwards.WithLabelValues(outcome).Inc()
}
