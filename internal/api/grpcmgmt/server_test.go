package grpcmgmt

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/resync"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeResyncModule struct {
	calls  atomic.Int32
	input  resync.Input
	result resync.Result
	err    error
}

func (f *fakeResyncModule) Resync(_ context.Context, input resync.Input) (resync.Result, error) {
	f.calls.Add(1)
	f.input = input
	return f.result, f.err
}

func ptrString(s string) *string {
	p := new(string)
	*p = s
	return p
}

func ptrWorkloadType(t model.WorkloadType) *model.WorkloadType {
	p := new(model.WorkloadType)
	*p = t
	return p
}

func ptrImageState(s resync.ImageState) *resync.ImageState {
	p := new(resync.ImageState)
	*p = s
	return p
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
		Cluster:       ptrString("c-1"),
		Namespace:     ptrString("ns-1"),
		Workload:      ptrString("wl-1"),
		WorkloadType:  ptrWorkloadType(model.WorkloadTypeApp),
		WorkloadState: resync.WorkloadState("updated"),
		ImageState:    ptrImageState(resync.ImageState(imageState)),
	}, module.input)
	require.Equal(t, &management.ResyncResponse{
		NumWorkloads: 1,
		Workloads:    []string{"c-1/ns-1/app/wl-1"},
	}, resp)
	require.Equal(t, int32(1), module.calls.Load())
}

func TestResyncRejectsInvalidStates(t *testing.T) {
	t.Parallel()

	module := &fakeResyncModule{}

	s := &Server{
		resync: module,
		log:    logrus.NewEntry(logrus.StandardLogger()),
	}

	t.Run("workload state", func(t *testing.T) {
		t.Parallel()

		invalid := "definitely-not-valid"
		resp, err := s.Resync(context.Background(), &management.ResyncRequest{
			WorkloadState: &invalid,
		})
		require.Nil(t, resp)
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Zero(t, module.calls.Load())
	})

	t.Run("image state", func(t *testing.T) {
		t.Parallel()

		invalid := "definitely-not-valid"
		resp, err := s.Resync(context.Background(), &management.ResyncRequest{
			ImageState: &invalid,
		})
		require.Nil(t, resp)
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Zero(t, module.calls.Load())
	})
}

func TestResyncReturnsPartialResultsOnModuleError(t *testing.T) {
	t.Parallel()

	module := &fakeResyncModule{
		err: errors.New("partial failure"),
		result: resync.Result{
			NumWorkloads: 1,
			Workloads:    []string{"c-1/ns-1/app/wl-1"},
			NumFailures:  1,
			Failures: []resync.Failure{
				{Subject: "c-1/ns-1/app/wl-2", Reason: "add workload failed"},
			},
		},
	}

	s := &Server{
		resync: module,
		log:    logrus.NewEntry(logrus.StandardLogger()),
	}

	workloadState := "updated"
	resp, err := s.Resync(context.Background(), &management.ResyncRequest{
		Cluster:       ptrString("c-1"),
		Namespace:     ptrString("ns-1"),
		Workload:      ptrString("wl-1"),
		WorkloadType:  ptrString("app"),
		WorkloadState: &workloadState,
	})
	require.NoError(t, err)
	require.Equal(t, &management.ResyncResponse{
		NumWorkloads: 1,
		Workloads:    []string{"c-1/ns-1/app/wl-1"},
		NumFailures:  1,
		Failures: []*management.ResyncFailure{
			{Subject: "c-1/ns-1/app/wl-2", Reason: "add workload failed"},
		},
	}, resp)
}

func TestResyncReturnsErrorOnFatalModuleFailure(t *testing.T) {
	t.Parallel()

	module := &fakeResyncModule{
		err: errors.New("database down"),
	}

	s := &Server{
		resync: module,
		log:    logrus.NewEntry(logrus.StandardLogger()),
	}

	workloadState := "updated"
	resp, err := s.Resync(context.Background(), &management.ResyncRequest{
		Cluster:       ptrString("c-1"),
		Namespace:     ptrString("ns-1"),
		Workload:      ptrString("wl-1"),
		WorkloadType:  ptrString("app"),
		WorkloadState: &workloadState,
	})
	require.Nil(t, resp)
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
}
