package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

func TestNewUpdaterMetricsSurviveWorkloadSnapshotRefresh(t *testing.T) {
	ResetUpdaterMetrics()
	t.Cleanup(ResetUpdaterMetrics)
	ObserveUpdaterStage("source_fetch", 240*time.Second, true)
	ObserveUpdaterStage("write_batch", 900*time.Second, true)
	RecordUpdaterImages("fetch", 3, false)
	RecordUpdaterImages("write", 2, false)
	RecordUpdaterImages("write", 1, true)
	RecordUpdaterResyncCycle(UpdaterResyncCycleOutcomeSuccess)

	ResetWorkloadMetrics()
	families := gatheredMetrics(t, Collectors()...)
	for stage, seconds := range map[string]float64{"source_fetch": 240, "write_batch": 900} {
		metric := findUpdaterMetric(t, families["nais_v13s_updater_stage_duration_seconds"], stage, "failed")
		require.Equal(t, uint64(1), metric.GetHistogram().GetSampleCount())
		require.Equal(t, seconds, metric.GetHistogram().GetSampleSum())
		var finiteBucket bool
		for _, bucket := range metric.GetHistogram().Bucket {
			if bucket.GetUpperBound() == seconds && bucket.GetCumulativeCount() == 1 {
				finiteBucket = true
			}
		}
		require.True(t, finiteBucket, "timeout-length observations must not fall exclusively in +Inf")
	}
	images := families["nais_v13s_updater_images_total"]
	require.Equal(t, 3.0, findUpdaterMetric(t, images, "fetch", "success").GetCounter().GetValue())
	require.Equal(t, 2.0, findUpdaterMetric(t, images, "write", "success").GetCounter().GetValue())
	require.Equal(t, 1.0, findUpdaterMetric(t, images, "write", "failed").GetCounter().GetValue())
	require.NotContains(t, families, "nais_v13s_updater_resync_cycles_total")
}

func findUpdaterMetric(t *testing.T, family *dto.MetricFamily, stage, outcome string) *dto.Metric {
	t.Helper()
	require.NotNil(t, family)
	for _, metric := range family.Metric {
		labels := make(map[string]string)
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["stage"] == stage && labels["outcome"] == outcome {
			require.Len(t, labels, 2)
			return metric
		}
	}
	t.Fatalf("metric missing for stage %q, outcome %q", stage, outcome)
	return nil
}
