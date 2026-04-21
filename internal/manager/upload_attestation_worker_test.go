package manager

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
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

func makeUploadAttestationJob(imageName, imageTag string, workloadId pgtype.UUID, attestation []byte) *river.Job[UploadAttestationJob] {
	return &river.Job[UploadAttestationJob]{
		JobRow: &rivertype.JobRow{
			Attempt:     1,
			MaxAttempts: 4,
		},
		Args: UploadAttestationJob{
			ImageName:   imageName,
			ImageTag:    imageTag,
			WorkloadId:  workloadId,
			Attestation: attestation,
		},
	}
}

func TestUploadAttestationWorker_SourceRefAlive_UpdatesWorkloads(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"
	workloadId := pgtype.UUID{Bytes: [16]byte{4}, Valid: true}
	sourceName := "dependencytrack"

	// Source reports its name for the GetSourceRef lookup
	source.EXPECT().Name().Return(sourceName)

	// Source ref exists in DB
	sourceRef := &sql.SourceRef{ImageName: imageName, ImageTag: imageTag}
	db.EXPECT().GetSourceRef(mock.Anything, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: sourceName,
	}).Return(sourceRef, nil)

	// Project is alive upstream
	source.EXPECT().ProjectExists(mock.Anything, imageName, imageTag).Return(true, nil)

	// Image → resync (ready_for_resync_at = now)
	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.Name == imageName && p.Tag == imageTag &&
			p.State == sql.ImageStateResync &&
			p.ReadyForResyncAt.Valid
	})).Return(int64(1), nil)

	// All workloads for this image → updated
	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, sql.UpdateWorkloadStateByImageParams{
		State:     sql.WorkloadStateUpdated,
		ImageName: imageName,
		ImageTag:  imageTag,
	}).Return(nil)

	// No upload, no finalize job enqueued
	worker := &UploadAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logger,
	}

	job := makeUploadAttestationJob(imageName, imageTag, workloadId, nil)
	err := worker.Work(ctx, job)

	require.NoError(t, err)
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}

func TestUploadAttestationWorker_SourceRefMissing_DoesNotUpdateWorkloadEarly(t *testing.T) {
	ctx := context.Background()
	logger, _ := test.NewNullLogger()

	db := mockquerier.NewMockQuerier(t)
	source := mocksource.NewMockSource(t)

	imageName := "my-image"
	imageTag := "v1.0"
	workloadId := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}
	sourceName := "dependencytrack"

	source.EXPECT().Name().Return(sourceName)

	// No source ref in DB
	db.EXPECT().GetSourceRef(mock.Anything, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTag,
		SourceType: sourceName,
	}).Return(nil, pgx.ErrNoRows)

	// No ProjectExists call expected — source_ref_missing skips it
	// No UpdateWorkloadStateByImage expected at this point — that only happens in finalize
	worker := &UploadAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logger,
	}

	job := makeUploadAttestationJob(imageName, imageTag, workloadId, []byte{})
	err := worker.Work(ctx, job)

	require.Error(t, err, "expected decompression error for empty attestation payload")
	db.AssertExpectations(t)
	source.AssertExpectations(t)
}
