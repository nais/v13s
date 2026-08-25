package grpcmgmt

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/nais/v13s/internal/resync"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type fakeResyncModule struct {
	calls  atomic.Int32
	input  resync.Input
	result resync.Result
}

func (f *fakeResyncModule) Resync(_ context.Context, input resync.Input) (resync.Result, error) {
	f.calls.Add(1)
	f.input = input
	return f.result, nil
}

func ptrString(s string) *string {
	return &s
}

func TestResyncDelegatesToModule(t *testing.T) {
	t.Parallel()

	module := &fakeResyncModule{result: resync.Result{
		NumWorkloads: 1,
		Workloads:    []string{"c-1/ns-1/app/wl-1"},
	}}

	s := &Server{
		resync: module,
		log:    logrus.NewEntry(logrus.StandardLogger()),
	}

	workloadState := "updated"
	imageState := "resync"
	resp, err := s.Resync(context.Background(), &management.ResyncRequest{
		Cluster:       ptrString("c-1"),
		Namespace:     ptrString("ns-1"),
		Workload:      ptrString("wl-1"),
		WorkloadType:  ptrString("app"),
		WorkloadState: &workloadState,
		ImageState:    &imageState,
	})
	require.NoError(t, err)
	require.Equal(t, resync.Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: "updated",
		ImageState:    &imageState,
	}, module.input)
	require.Equal(t, &management.ResyncResponse{
		NumWorkloads: 1,
		Workloads:    []string{"c-1/ns-1/app/wl-1"},
	}, resp)
	require.Equal(t, int32(1), module.calls.Load())
}
