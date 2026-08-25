package metrics

import "github.com/prometheus/client_golang/prometheus"

type UpdaterResyncCycleOutcome string

const (
	UpdaterResyncCycleOutcomeSuccess UpdaterResyncCycleOutcome = "success"
	UpdaterResyncCycleOutcomeFailed  UpdaterResyncCycleOutcome = "failed"
	UpdaterResyncCycleOutcomeSkipped UpdaterResyncCycleOutcome = "skipped"
)

var UpdaterResyncCycles = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "updater_resync_cycles_total",
		Help:      "Number of updater resync cycles by outcome.",
	},
	[]string{"outcome"},
)

func RecordUpdaterResyncCycle(outcome UpdaterResyncCycleOutcome) {
	recordUpdaterResyncCycle(UpdaterResyncCycles, outcome)
}

func ResetUpdaterMetrics() {
	UpdaterResyncCycles.Reset()
}

func recordUpdaterResyncCycle(counter *prometheus.CounterVec, outcome UpdaterResyncCycleOutcome) {
	counter.WithLabelValues(string(outcome)).Inc()
}
