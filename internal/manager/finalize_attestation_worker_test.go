package manager

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	srcmock "github.com/nais/v13s/internal/mocks/Source"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeFinalizeJob(processToken string) *river.Job[FinalizeAttestationJob] {
	return &river.Job[FinalizeAttestationJob]{
		JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: 15},
		Args: FinalizeAttestationJob{
			ImageName:    "myimage",
			ImageTag:     "v1",
			ProcessToken: processToken,
		},
	}
}

func TestFinalizeAttestationWorker_UpdatesWorkloadStateByImage_OnTaskComplete(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)

	source.EXPECT().IsTaskInProgress(mock.Anything, "token-123").Return(false, nil)

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.Name == "myimage" && p.Tag == "v1" && p.State == sql.ImageStateResync
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateByImageParams) bool {
		return p.ImageName == "myimage" && p.ImageTag == "v1" && p.State == sql.WorkloadStateProcessing
	})).Return(nil)

	db.EXPECT().ListUnusedSourceRefs(mock.Anything, mock.Anything).Return(nil, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
	}

	job := makeFinalizeJob("token-123")
	err := worker.Work(ctx, job)
	require.NoError(t, err)
}

func TestFinalizeAttestationWorker_StillInProgress_DoesNotUpdateWorkloadState(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)

	source.EXPECT().IsTaskInProgress(mock.Anything, "token-456").Return(true, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
	}

	job := makeFinalizeJob("token-456")
	err := worker.Work(ctx, job)
	require.Error(t, err)
	db.AssertNotCalled(t, "UpdateWorkloadStateByImage", mock.Anything, mock.Anything)
}

func TestFinalizeAttestationWorker_EmptyToken_UpdatesWorkloadStateByImage(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.State == sql.ImageStateResync
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateByImageParams) bool {
		return p.State == sql.WorkloadStateProcessing
	})).Return(nil)

	db.EXPECT().ListUnusedSourceRefs(mock.Anything, mock.Anything).Return(nil, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
	}

	job := makeFinalizeJob("")
	err := worker.Work(ctx, job)
	require.NoError(t, err)
}
