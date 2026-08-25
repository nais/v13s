package resync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/metrics"
	"github.com/nais/v13s/internal/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type inMemoryQuerier struct {
	mu                   sync.Mutex
	rows                 []*sql.SetWorkloadStateRow
	setWorkloadStateErr  error
	updateImageStateErrs map[string]error
	setWorkloadCalls     []sql.SetWorkloadStateParams
	updateImageCalls     []sql.UpdateImageStateParams
}

func newInMemoryQuerier(rows ...*sql.SetWorkloadStateRow) *inMemoryQuerier {
	return &inMemoryQuerier{
		rows:                 rows,
		updateImageStateErrs: map[string]error{},
	}
}

func (q *inMemoryQuerier) SetWorkloadState(_ context.Context, arg sql.SetWorkloadStateParams) ([]*sql.SetWorkloadStateRow, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.setWorkloadCalls = append(q.setWorkloadCalls, arg)
	if q.setWorkloadStateErr != nil {
		return nil, q.setWorkloadStateErr
	}

	rows := make([]*sql.SetWorkloadStateRow, len(q.rows))
	copy(rows, q.rows)
	return rows, nil
}

func (q *inMemoryQuerier) UpdateImageState(_ context.Context, arg sql.UpdateImageStateParams) (int64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.updateImageCalls = append(q.updateImageCalls, arg)
	if err, ok := q.updateImageStateErrs[imageKey(arg.Name, arg.Tag)]; ok {
		return 0, err
	}
	return 1, nil
}

func (q *inMemoryQuerier) SetWorkloadCalls() []sql.SetWorkloadStateParams {
	q.mu.Lock()
	defer q.mu.Unlock()

	calls := make([]sql.SetWorkloadStateParams, len(q.setWorkloadCalls))
	copy(calls, q.setWorkloadCalls)
	return calls
}

func (q *inMemoryQuerier) UpdateImageCalls() []sql.UpdateImageStateParams {
	q.mu.Lock()
	defer q.mu.Unlock()

	calls := make([]sql.UpdateImageStateParams, len(q.updateImageCalls))
	copy(calls, q.updateImageCalls)
	return calls
}

type inMemoryEnqueuer struct {
	mu        sync.Mutex
	calls     []*model.Workload
	failOn    int
	failError error
}

func (e *inMemoryEnqueuer) AddWorkload(_ context.Context, workload *model.Workload) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.calls = append(e.calls, workload)
	if e.failOn > 0 && len(e.calls) == e.failOn {
		if e.failError != nil {
			return e.failError
		}
		return errors.New("add workload failed")
	}
	return nil
}

func (e *inMemoryEnqueuer) Calls() []*model.Workload {
	e.mu.Lock()
	defer e.mu.Unlock()

	calls := make([]*model.Workload, len(e.calls))
	copy(calls, e.calls)
	return calls
}

type inMemoryUpdater struct {
	calls atomic.Int32
}

func (u *inMemoryUpdater) RunCycle(_ context.Context) error {
	u.calls.Add(1)
	return nil
}

func ptrString(s string) *string {
	return &s
}

func imageKey(name, tag string) string {
	return strings.Join([]string{name, tag}, "\x00")
}

func TestWorkloadResyncModule_ResyncNoOp(t *testing.T) {
	t.Parallel()

	querier := newInMemoryQuerier()
	enqueuer := &inMemoryEnqueuer{}
	updater := &inMemoryUpdater{}
	module := NewWorkloadResyncModule(context.Background(), querier, enqueuer, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}
	var moduleIface Module = module

	result, err := moduleIface.Resync(context.Background(), Input{
		Cluster:       "c-1",
		Namespace:     "ns-1",
		Workload:      "wl-1",
		WorkloadType:  ptrString("app"),
		WorkloadState: sql.WorkloadStateUpdated,
	})
	require.NoError(t, err)
	require.Equal(t, Result{Workloads: []string{}}, result)
	require.Equal(t, []metrics.WorkloadResyncOutcome{metrics.WorkloadResyncOutcomeNoOp}, recorded)
	require.Empty(t, enqueuer.Calls())
	require.Empty(t, querier.UpdateImageCalls())
	require.Zero(t, updater.calls.Load())
}

func TestWorkloadResyncModule_ResyncContinuesAfterRowFailure(t *testing.T) {
	t.Parallel()

	querier := newInMemoryQuerier(
		&sql.SetWorkloadStateRow{Name: "wl-1", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-1", ImageTag: "v1"},
		&sql.SetWorkloadStateRow{Name: "wl-2", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-2", ImageTag: "v2"},
		&sql.SetWorkloadStateRow{Name: "wl-3", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-3", ImageTag: "v3"},
	)
	enqueuer := &inMemoryEnqueuer{failOn: 2}
	updater := &inMemoryUpdater{}
	module := NewWorkloadResyncModule(context.Background(), querier, enqueuer, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}
	var moduleIface Module = module

	result, err := moduleIface.Resync(context.Background(), Input{
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
	require.Len(t, enqueuer.Calls(), 3)
	require.Empty(t, querier.UpdateImageCalls())
	require.Zero(t, updater.calls.Load())
}

func TestWorkloadResyncModule_ResyncDedupsImages(t *testing.T) {
	t.Parallel()

	querier := newInMemoryQuerier(
		&sql.SetWorkloadStateRow{Name: "wl-1", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-1", ImageTag: "v1"},
		&sql.SetWorkloadStateRow{Name: "wl-2", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-1", ImageTag: "v1"},
	)
	enqueuer := &inMemoryEnqueuer{}
	updater := &inMemoryUpdater{}
	module := NewWorkloadResyncModule(context.Background(), querier, enqueuer, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}
	var moduleIface Module = module

	imageState := "resync"
	result, err := moduleIface.Resync(context.Background(), Input{
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

	require.Len(t, querier.UpdateImageCalls(), 1)
	require.Eventually(t, func() bool {
		return updater.calls.Load() == 1
	}, time.Second, 20*time.Millisecond)
}

func TestWorkloadResyncModule_ResyncTriggersUpdaterOncePerRequest(t *testing.T) {
	t.Parallel()

	querier := newInMemoryQuerier(
		&sql.SetWorkloadStateRow{Name: "wl-1", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-1", ImageTag: "v1"},
		&sql.SetWorkloadStateRow{Name: "wl-2", WorkloadType: "app", Namespace: "ns-1", Cluster: "c-1", ImageName: "img-2", ImageTag: "v2"},
	)
	enqueuer := &inMemoryEnqueuer{}
	updater := &inMemoryUpdater{}
	module := NewWorkloadResyncModule(context.Background(), querier, enqueuer, updater, logrus.New())
	var recorded []metrics.WorkloadResyncOutcome
	module.recordOutcome = func(outcome metrics.WorkloadResyncOutcome) {
		recorded = append(recorded, outcome)
	}
	var moduleIface Module = module

	imageState := "resync"
	result, err := moduleIface.Resync(context.Background(), Input{
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

	require.Len(t, querier.UpdateImageCalls(), 2)
	require.Eventually(t, func() bool {
		return updater.calls.Load() == 1
	}, time.Second, 20*time.Millisecond)
}
