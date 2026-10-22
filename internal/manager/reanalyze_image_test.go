package manager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	srcmock "github.com/nais/v13s/internal/mocks/Source"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestReanalyzeQueuesEachImageOnce(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	images := []*sql.ListImagesForReanalysisRow{
		{ImageName: "image-a", ImageTag: "v1"},
		{ImageName: "image-b", ImageTag: "v2"},
	}
	db.EXPECT().ListImagesForReanalysis(mock.Anything, sql.ListImagesForReanalysisParams{
		Cluster: "dev", Namespace: "team", MaxImages: MaxReanalysisImages + 1,
	}).Return(images, nil)
	jobs := &trackingJobClient{}
	m := &WorkloadManager{db: db, jobClient: jobs}

	count, err := m.Reanalyze(context.Background(), sql.ListImagesForReanalysisParams{
		Cluster: "dev", Namespace: "team",
	})
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.Len(t, jobs.addedJobs, 2)
	first := jobs.addedJobs[0].(*ReanalyzeImageJob)
	second := jobs.addedJobs[1].(*ReanalyzeImageJob)
	require.Equal(t, "image-a", first.ImageName)
	require.Equal(t, "v1", first.ImageTag)
	require.Equal(t, "image-b", second.ImageName)
	require.Equal(t, "v2", second.ImageTag)
	require.Equal(t, 2*time.Second, second.ScheduledAt.Sub(first.ScheduledAt))
}

func TestReanalyzeAccepts250Images(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	images := make([]*sql.ListImagesForReanalysisRow, MaxReanalysisImages)
	for i := range images {
		images[i] = &sql.ListImagesForReanalysisRow{ImageName: "image", ImageTag: fmt.Sprint(i)}
	}
	db.EXPECT().ListImagesForReanalysis(mock.Anything, sql.ListImagesForReanalysisParams{
		Cluster: "dev", Namespace: "team", MaxImages: MaxReanalysisImages + 1,
	}).Return(images, nil)
	jobs := &trackingJobClient{}
	count, err := (&WorkloadManager{db: db, jobClient: jobs}).Reanalyze(
		context.Background(), sql.ListImagesForReanalysisParams{Cluster: "dev", Namespace: "team"},
	)
	require.NoError(t, err)
	require.Equal(t, 250, count)
	require.Len(t, jobs.addedJobs, 250)
}

func TestReanalyzeRejectsOversizedNamespaceWithoutQueuing(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	db.EXPECT().ListImagesForReanalysis(mock.Anything, sql.ListImagesForReanalysisParams{
		Cluster: "dev", Namespace: "team", MaxImages: MaxReanalysisImages + 1,
	}).
		Return(make([]*sql.ListImagesForReanalysisRow, MaxReanalysisImages+1), nil)
	jobs := &trackingJobClient{}

	_, err := (&WorkloadManager{db: db, jobClient: jobs}).Reanalyze(
		context.Background(), sql.ListImagesForReanalysisParams{Cluster: "dev", Namespace: "team"},
	)
	require.ErrorIs(t, err, ErrReanalysisLimit)
	require.Empty(t, jobs.addedJobs)
}

func TestReanalyzeWorkerStartsProjectAnalysis(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)
	db.EXPECT().ImageHasWorkload(mock.Anything, sql.ImageHasWorkloadParams{
		ImageName: "image-a", ImageTag: "v1",
	}).Return(true, nil)
	source.EXPECT().TriggerAnalysis(mock.Anything, "image-a", "v1").Return("token", nil)
	jobs := &trackingJobClient{}
	worker := &ReanalyzeImageWorker{db: db, source: source, jobClient: jobs}

	err := worker.Work(context.Background(), &river.Job[ReanalyzeImageJob]{
		Args: ReanalyzeImageJob{ImageName: "image-a", ImageTag: "v1"},
	})
	require.NoError(t, err)
	require.Equal(t, []river.JobArgs{
		&FinishReanalysisJob{ImageName: "image-a", ImageTag: "v1", ProcessToken: "token"},
	}, jobs.addedJobs)
}

func TestFinishReanalysisWaitsBeforeResync(t *testing.T) {
	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)
	source.EXPECT().IsTaskInProgress(mock.Anything, "token").Return(true, nil)
	worker := &FinishReanalysisWorker{db: db, source: source}

	err := worker.Work(context.Background(), &river.Job[FinishReanalysisJob]{
		Args: FinishReanalysisJob{ImageName: "image-a", ImageTag: "v1", ProcessToken: "token"},
	})
	var snooze *river.JobSnoozeError
	require.ErrorContains(t, err, "still in progress")
	require.NotErrorAs(t, err, &snooze)
	db.AssertNotCalled(t, "UpdateImageState", mock.Anything, mock.Anything)
}

func TestFinishReanalysisRetriesProgressCheckErrors(t *testing.T) {
	source := srcmock.NewMockSource(t)
	source.EXPECT().IsTaskInProgress(mock.Anything, "token").Return(false, errors.New("source unavailable"))
	worker := &FinishReanalysisWorker{source: source}

	err := worker.Work(context.Background(), &river.Job[FinishReanalysisJob]{
		Args: FinishReanalysisJob{ImageName: "image-a", ImageTag: "v1", ProcessToken: "token"},
	})
	require.ErrorContains(t, err, "source unavailable")
	var snooze *river.JobSnoozeError
	require.NotErrorAs(t, err, &snooze)
}

func TestFinishReanalysisRetriesErrorsAfterOneMinute(t *testing.T) {
	worker := FinishReanalysisWorker{}
	before := time.Now()
	next := worker.NextRetry(nil)
	require.WithinDuration(t, before.Add(time.Minute), next, time.Second)
}

func TestFinishReanalysisResyncsOnlyCurrentImage(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "unused", true: "active"}[active], func(t *testing.T) {
			db := sqmock.NewMockQuerier(t)
			source := srcmock.NewMockSource(t)
			source.EXPECT().IsTaskInProgress(mock.Anything, "token").Return(false, nil)
			db.EXPECT().ImageHasWorkload(mock.Anything, sql.ImageHasWorkloadParams{
				ImageName: "image-a", ImageTag: "v1",
			}).Return(active, nil)
			if active {
				db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
					return p.Name == "image-a" && p.Tag == "v1" && p.State == sql.ImageStateResync && p.ReadyForResyncAt.Valid
				})).Return(int64(1), nil)
			}
			worker := &FinishReanalysisWorker{db: db, source: source}
			err := worker.Work(context.Background(), &river.Job[FinishReanalysisJob]{
				Args: FinishReanalysisJob{ImageName: "image-a", ImageTag: "v1", ProcessToken: "token"},
			})
			if active {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				db.AssertNotCalled(t, "UpdateImageState", mock.Anything, mock.Anything)
			}
		})
	}
}
