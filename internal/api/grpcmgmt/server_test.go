package grpcmgmt

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	dbsql "github.com/nais/v13s/internal/database/sql"
	mocksql "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/pkg/api/vulnerabilities/management"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeWorkloadManager struct {
	addCalls atomic.Int32
}

func (f *fakeWorkloadManager) AddWorkload(_ context.Context, _ *model.Workload) error {
	f.addCalls.Add(1)
	return nil
}

func (f *fakeWorkloadManager) DeleteWorkload(_ context.Context, _ *model.Workload) error {
	return nil
}

type fakeResyncRunner struct {
	runCalls atomic.Int32
}

func (f *fakeResyncRunner) RunCycle(_ context.Context) error {
	f.runCalls.Add(1)
	return nil
}

func TestResyncCallsRunCycle(t *testing.T) {
	t.Parallel()

	querier := new(mocksql.MockQuerier)
	mgr := &fakeWorkloadManager{}
	runner := &fakeResyncRunner{}

	querier.EXPECT().
		SetWorkloadState(mock.Anything, mock.Anything).
		Return([]*dbsql.SetWorkloadStateRow{
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
		UpdateImageState(mock.Anything, mock.MatchedBy(func(arg dbsql.UpdateImageStateParams) bool {
			return arg.Name == "img-1" && arg.Tag == "v1" && arg.ReadyForResyncAt.Valid
		})).
		Return(int64(1), nil).
		Once()

	s := &Server{
		querier:   querier,
		mgr:       mgr,
		updater:   runner,
		parentCtx: context.Background(),
		log:       logrus.NewEntry(logrus.StandardLogger()),
	}

	imageState := string(dbsql.ImageStateResync)
	_, err := s.Resync(context.Background(), &management.ResyncRequest{
		ImageState: &imageState,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return runner.runCalls.Load() == 1
	}, time.Second, 20*time.Millisecond)
	require.Equal(t, int32(1), mgr.addCalls.Load())
	querier.AssertExpectations(t)
}
