package resync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	mocksql "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeEnqueuer struct {
	calls atomic.Int32
}

func (f *fakeEnqueuer) AddWorkload(_ context.Context, _ *model.Workload) error {
	f.calls.Add(1)
	return nil
}

type failingEnqueuer struct {
	calls  atomic.Int32
	failOn int32
}

func (f *failingEnqueuer) AddWorkload(_ context.Context, _ *model.Workload) error {
	call := f.calls.Add(1)
	if call == f.failOn {
		return context.Canceled
	}
	return nil
}

type fakeUpdater struct {
	calls atomic.Int32
}

func (f *fakeUpdater) RunCycle(_ context.Context) error {
	f.calls.Add(1)
	return nil
}

func ptrString(s string) *string {
	return &s
}

func TestWorkloadResyncModule_ResyncEnqueuesWorkloadsAndTriggersUpdaterOnce(t *testing.T) {
	t.Parallel()

	querier := mocksql.NewMockQuerier(t)
	mgr := &fakeEnqueuer{}
	updater := &fakeUpdater{}

	querier.EXPECT().
		SetWorkloadState(mock.Anything, sql.SetWorkloadStateParams{
			Cluster:      ptrString("c-1"),
			Namespace:    ptrString("ns-1"),
			WorkloadName: ptrString("wl-1"),
			WorkloadType: ptrString("app"),
			OldState:     sql.WorkloadStateUpdated,
			State:        sql.WorkloadStateResync,
		}).
		Return([]*sql.SetWorkloadStateRow{
			{
				Name:         "wl-1",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-1",
				ImageTag:     "v1",
			},
		}, nil).
		Once()

	querier.EXPECT().
		UpdateImageState(mock.Anything, mock.MatchedBy(func(arg sql.UpdateImageStateParams) bool {
			return arg.Name == "img-1" && arg.Tag == "v1" && arg.ReadyForResyncAt.Valid
		})).
		Return(int64(1), nil).
		Once()

	module := NewWorkloadResyncModule(context.Background(), querier, mgr, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}

	imageState := "resync"
	result, err := module.Resync(context.Background(), Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: sql.WorkloadStateUpdated,
		ImageState:    &imageState,
	})
	require.NoError(t, err)
	require.Equal(t, Result{
		NumWorkloads: 1,
		Workloads:    []string{"c-1/ns-1/app/wl-1"},
	}, result)
	require.Equal(t, []metrics.WorkloadResyncOutcome{metrics.WorkloadResyncOutcomeSuccess}, recorded)

	require.Eventually(t, func() bool {
		return updater.calls.Load() == 1
	}, time.Second, 20*time.Millisecond)
	require.Equal(t, int32(1), mgr.calls.Load())
	querier.AssertExpectations(t)
}

func TestWorkloadResyncModule_ResyncReturnsEmptyResultForNoMatches(t *testing.T) {
	t.Parallel()

	querier := mocksql.NewMockQuerier(t)
	mgr := &fakeEnqueuer{}
	updater := &fakeUpdater{}

	querier.EXPECT().
		SetWorkloadState(mock.Anything, mock.Anything).
		Return([]*sql.SetWorkloadStateRow{}, nil).
		Once()

	module := NewWorkloadResyncModule(context.Background(), querier, mgr, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}

	result, err := module.Resync(context.Background(), Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: sql.WorkloadStateUpdated,
	})
	require.NoError(t, err)
	require.Equal(t, Result{Workloads: []string{}}, result)
	require.Equal(t, []metrics.WorkloadResyncOutcome{metrics.WorkloadResyncOutcomeNoOp}, recorded)
	require.Equal(t, int32(0), mgr.calls.Load())
	require.Equal(t, int32(0), updater.calls.Load())
	querier.AssertExpectations(t)
}

func TestWorkloadResyncModule_ResyncContinuesAfterRowFailure(t *testing.T) {
	t.Parallel()

	querier := mocksql.NewMockQuerier(t)
	mgr := &failingEnqueuer{failOn: 2}
	updater := &fakeUpdater{}

	querier.EXPECT().
		SetWorkloadState(mock.Anything, mock.Anything).
		Return([]*sql.SetWorkloadStateRow{
			{
				Name:         "wl-1",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-1",
				ImageTag:     "v1",
			},
			{
				Name:         "wl-2",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-2",
				ImageTag:     "v2",
			},
			{
				Name:         "wl-3",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-3",
				ImageTag:     "v3",
			},
		}, nil).
		Once()

	module := NewWorkloadResyncModule(context.Background(), querier, mgr, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}

	result, err := module.Resync(context.Background(), Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: sql.WorkloadStateUpdated,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "adding workload c-1/ns-1/app/wl-2")
	require.Equal(t, Result{
		NumWorkloads: 2,
		Workloads:    []string{"c-1/ns-1/app/wl-1", "c-1/ns-1/app/wl-3"},
	}, result)
	require.Equal(t, []metrics.WorkloadResyncOutcome{metrics.WorkloadResyncOutcomeFailed}, recorded)
	require.Equal(t, int32(3), mgr.calls.Load())
	require.Equal(t, int32(0), updater.calls.Load())
	querier.AssertExpectations(t)
}

func TestWorkloadResyncModule_ResyncDedupsImagesAndTriggersUpdaterOnce(t *testing.T) {
	t.Parallel()

	querier := mocksql.NewMockQuerier(t)
	mgr := &fakeEnqueuer{}
	updater := &fakeUpdater{}

	querier.EXPECT().
		SetWorkloadState(mock.Anything, mock.Anything).
		Return([]*sql.SetWorkloadStateRow{
			{
				Name:         "wl-1",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-1",
				ImageTag:     "v1",
			},
			{
				Name:         "wl-2",
				WorkloadType: "app",
				Namespace:    "ns-1",
				Cluster:      "c-1",
				ImageName:    "img-1",
				ImageTag:     "v1",
			},
		}, nil).
		Once()

	querier.EXPECT().
		UpdateImageState(mock.Anything, mock.MatchedBy(func(arg sql.UpdateImageStateParams) bool {
			return arg.Name == "img-1" && arg.Tag == "v1" && arg.ReadyForResyncAt.Valid
		})).
		Return(int64(1), nil).
		Once()

	module := NewWorkloadResyncModule(context.Background(), querier, mgr, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}

	imageState := "resync"
	result, err := module.Resync(context.Background(), Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: sql.WorkloadStateUpdated,
		ImageState:    &imageState,
	})
	require.NoError(t, err)
	require.Equal(t, Result{
		NumWorkloads: 2,
		Workloads:    []string{"c-1/ns-1/app/wl-1", "c-1/ns-1/app/wl-2"},
	}, result)
	require.Equal(t, []metrics.WorkloadResyncOutcome{metrics.WorkloadResyncOutcomeSuccess}, recorded)

	require.Eventually(t, func() bool {
		return updater.calls.Load() == 1
	}, time.Second, 20*time.Millisecond)
	require.Equal(t, int32(2), mgr.calls.Load())
	querier.AssertExpectations(t)
}
