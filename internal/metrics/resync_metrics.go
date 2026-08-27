package metrics

import "github.com/prometheus/client_golang/prometheus"

type WorkloadResyncOutcome string

const (
	WorkloadResyncOutcomeSuccess WorkloadResyncOutcome = "success"
	WorkloadResyncOutcomeNoOp    WorkloadResyncOutcome = "no_op"
	WorkloadResyncOutcomeFailed  WorkloadResyncOutcome = "failed"
)

var WorkloadResyncRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "workload_resync_requests_total",
		Help:      "Number of workload resync requests by outcome.",
	},
	[]string{"outcome"},
)

func RecordWorkloadResyncOutcome(outcome WorkloadResyncOutcome) {
	recordWorkloadResyncOutcome(WorkloadResyncRequests, outcome)
}

func ResetWorkloadResyncMetrics() {
	WorkloadResyncRequests.Reset()
}

func recordWorkloadResyncOutcome(counter *prometheus.CounterVec, outcome WorkloadResyncOutcome) {
	counter.WithLabelValues(string(outcome)).Inc()
}
