package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestRecordWorkloadResyncOutcome(t *testing.T) {
	ResetWorkloadResyncMetrics()
	reg := prometheus.NewRegistry()
	reg.MustRegister(WorkloadResyncRequests)
	t.Cleanup(ResetWorkloadResyncMetrics)

	RecordWorkloadResyncOutcome(WorkloadResyncOutcomeSuccess)
	RecordWorkloadResyncOutcome(WorkloadResyncOutcomeSuccess)
	RecordWorkloadResyncOutcome(WorkloadResyncOutcomeNoOp)
	RecordWorkloadResyncOutcome(WorkloadResyncOutcomeFailed)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var success, noop, failed float64
	for _, mf := range mfs {
		if mf.GetName() != "nais_v13s_workload_resync_requests_total" {
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
			case "success":
				success = metric.GetCounter().GetValue()
			case "no_op":
				noop = metric.GetCounter().GetValue()
			case "failed":
				failed = metric.GetCounter().GetValue()
			}
		}
	}

	require.Equal(t, 2.0, success)
	require.Equal(t, 1.0, noop)
	require.Equal(t, 1.0, failed)
}

func TestCollectorsIncludesWorkloadResyncRequests(t *testing.T) {
	t.Helper()

	collectors := Collectors()
	require.Contains(t, collectors, WorkloadResyncRequests)
}

func TestResetWorkloadMetricsResetsWorkloadResyncRequests(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(WorkloadResyncRequests)

	RecordWorkloadResyncOutcome(WorkloadResyncOutcomeSuccess)
	before, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, before)

	ResetWorkloadMetrics()

	after, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range after {
		if mf.GetName() == "nais_v13s_workload_resync_requests_total" {
			require.Empty(t, mf.GetMetric())
			return
		}
	}
}
