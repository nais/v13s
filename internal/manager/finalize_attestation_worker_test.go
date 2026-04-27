package manager

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	mockquerier "github.com/nais/v13s/internal/mocks/Querier"
	mocksource "github.com/nais/v13s/internal/mocks/Source"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeFinalizeJob(imageName, imageTag, processToken string) *river.Job[FinalizeAttestationJob] {
	return &river.Job[FinalizeAttestationJob]{
		JobRow: &rivertype.JobRow{
			Attempt:     1,
			MaxAttempts: 15,
		},
		Args: FinalizeAttestationJob{
			ImageName:    imageName,
			ImageTag:     imageTag,
			ProcessToken: processToken,
		},
	}
}

func TestFinalizeAttestationWorker_TaskComplete_UpdatesWorkloads(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"
	processToken := "token-abc"

	source.EXPECT().IsTaskInProgress(mock.Anything, processToken).Return(false, nil)

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.Name == imageName && p.Tag == imageTag && p.State == sql.ImageStateResync && p.ReadyForResyncAt.Valid
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, sql.UpdateWorkloadStateByImageParams{
		State:     sql.WorkloadStateUpdated,
		ImageName: imageName,
		ImageTag:  imageTag,
	}).Return(nil)

	db.EXPECT().ListUnusedSourceRefs(mock.Anything, &imageName).Return(nil, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logger,
	}

	job := makeFinalizeJob(imageName, imageTag, processToken)
	err := worker.Work(ctx, job)

	require.NoError(t, err)
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}

func TestFinalizeAttestationWorker_TaskInProgress_RetryLater(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"
	processToken := "token-xyz"

	source.EXPECT().IsTaskInProgress(mock.Anything, processToken).Return(true, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logger,
	}

	job := makeFinalizeJob(imageName, imageTag, processToken)
	err := worker.Work(ctx, job)

	require.Error(t, err, "expected error to trigger River retry when task is in progress")
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}

func TestFinalizeAttestationWorker_EmptyToken_TreatedAsComplete(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.Name == imageName && p.Tag == imageTag &&
			p.State == sql.ImageStateResync &&
			p.ReadyForResyncAt.Valid &&
			p.ReadyForResyncAt.Time.After(time.Now().Add(-time.Second))
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, sql.UpdateWorkloadStateByImageParams{
		State:     sql.WorkloadStateUpdated,
		ImageName: imageName,
		ImageTag:  imageTag,
	}).Return(nil)

	db.EXPECT().ListUnusedSourceRefs(mock.Anything, &imageName).Return(nil, nil)

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logger,
	}

	job := makeFinalizeJob(imageName, imageTag, "" /* empty token */)
	err := worker.Work(ctx, job)

	require.NoError(t, err)
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}

func TestFinalizeAttestationWorker_UpdatesWorkloads_WithUnusedSourceRefs(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"
	processToken := "token-def"

	source.EXPECT().IsTaskInProgress(mock.Anything, processToken).Return(false, nil)

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.State == sql.ImageStateResync
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, sql.UpdateWorkloadStateByImageParams{
		State:     sql.WorkloadStateUpdated,
		ImageName: imageName,
		ImageTag:  imageTag,
	}).Return(nil)

	unusedRef := &sql.SourceRef{
		ImageName: "old-image",
		ImageTag:  "old-tag",
	}
	db.EXPECT().ListUnusedSourceRefs(mock.Anything, &imageName).Return([]*sql.SourceRef{unusedRef}, nil)

	enqueueCount := 0
	jobClient := &capturingJobClient{onAdd: func(args river.JobArgs) {
		if _, ok := args.(*RemoveFromSourceJob); ok {
			enqueueCount++
		}
	}}

	worker := &FinalizeAttestationWorker{
		db:        db,
		source:    source,
		jobClient: jobClient,
		log:       logger,
	}

	job := makeFinalizeJob(imageName, imageTag, processToken)
	err := worker.Work(ctx, job)

	require.NoError(t, err)
	require.Equal(t, 1, enqueueCount, "expected 1 RemoveFromSourceJob to be enqueued")
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}

var _ = pgtype.Timestamptz{}
