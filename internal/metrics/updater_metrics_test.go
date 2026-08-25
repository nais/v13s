package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRecordUpdaterResyncCycle(t *testing.T) {
	reg := prometheus.NewRegistry()
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: Subsystem,
			Name:      "updater_resync_cycles_total",
			Help:      "Number of updater resync cycles by outcome.",
		},
		[]string{"outcome"},
	)
	reg.MustRegister(counter)

	recordUpdaterResyncCycle(counter, UpdaterResyncCycleOutcomeSkipped)
	recordUpdaterResyncCycle(counter, UpdaterResyncCycleOutcomeSkipped)
	recordUpdaterResyncCycle(counter, UpdaterResyncCycleOutcomeFailed)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var skipped, failed float64
	for _, mf := range mfs {
		if mf.GetName() != "nais_v13s_updater_resync_cycles_total" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			var outcome string
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "outcome" {
					outcome = lp.GetValue()
					break
				}
			}
			switch outcome {
			case "skipped":
				skipped = metric.GetCounter().GetValue()
			case "failed":
				failed = metric.GetCounter().GetValue()
			}
		}
	}

	require.Equal(t, 2.0, skipped)
	require.Equal(t, 1.0, failed)
}
