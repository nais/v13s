package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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

var UpdaterStageDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "updater_stage_duration_seconds",
		Help:      "Duration of updater operations by stage and outcome.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120, 240, 300, 600, 900, 1200, 1800},
	},
	[]string{"stage", "outcome"},
)

var UpdaterImages = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: Subsystem,
		Name:      "updater_images_total",
		Help:      "Image refresh attempts by stage (fetch and enqueue, or image-state write) and outcome.",
	},
	[]string{"stage", "outcome"},
)

func ObserveUpdaterStage(stage string, duration time.Duration, failed bool) {
	outcome := "success"
	if failed {
		outcome = "failed"
	}
	UpdaterStageDuration.WithLabelValues(stage, outcome).Observe(duration.Seconds())
}

func RecordUpdaterImages(stage string, count int, failed bool) {
	outcome := "success"
	if failed {
		outcome = "failed"
	}
	UpdaterImages.WithLabelValues(stage, outcome).Add(float64(count))
}

func RecordUpdaterResyncCycle(outcome UpdaterResyncCycleOutcome) {
	recordUpdaterResyncCycle(UpdaterResyncCycles, outcome)
}

func ResetUpdaterMetrics() {
	UpdaterResyncCycles.Reset()
	UpdaterStageDuration.Reset()
	UpdaterImages.Reset()
}

func recordUpdaterResyncCycle(counter *prometheus.CounterVec, outcome UpdaterResyncCycleOutcome) {
	counter.WithLabelValues(string(outcome)).Inc()
}
