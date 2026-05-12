package manager

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	sqmock "github.com/nais/v13s/internal/mocks/Querier"
	srcmock "github.com/nais/v13s/internal/mocks/Source"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func makeUploadJob() *river.Job[UploadAttestationJob] {
	wid := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	return &river.Job[UploadAttestationJob]{
		JobRow: &rivertype.JobRow{Attempt: 1, MaxAttempts: 4},
		Args: UploadAttestationJob{
			ImageName:   "myimage",
			ImageTag:    "v1",
			WorkloadId:  wid,
			Attestation: []byte{},
		},
	}
}

func TestUploadAttestationWorker_ResyncAndReturn_UpdatesWorkloadStateByImage(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)

	source.EXPECT().Name().Return("test-source")

	db.EXPECT().GetSourceRef(mock.Anything, mock.MatchedBy(func(p sql.GetSourceRefParams) bool {
		return p.ImageName == "myimage" && p.ImageTag == "v1"
	})).Return(&sql.SourceRef{
		ImageName: "myimage",
		ImageTag:  "v1",
	}, nil)

	source.EXPECT().ProjectExists(mock.Anything, "myimage", "v1").Return(true, nil)

	db.EXPECT().UpdateImageState(mock.Anything, mock.MatchedBy(func(p sql.UpdateImageStateParams) bool {
		return p.Name == "myimage" && p.Tag == "v1" && p.State == sql.ImageStateResync
	})).Return(int64(1), nil)

	db.EXPECT().UpdateWorkloadStateByImage(mock.Anything, mock.MatchedBy(func(p sql.UpdateWorkloadStateByImageParams) bool {
		return p.ImageName == "myimage" && p.ImageTag == "v1" && p.State == sql.WorkloadStateProcessing
	})).Return(nil)

	worker := &UploadAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
	}

	job := makeUploadJob()
	err := worker.Work(ctx, job)
	require.NoError(t, err)
}

func TestUploadAttestationWorker_NoSourceRef_DoesNotUpdateWorkloadStateByImage(t *testing.T) {
	ctx := context.Background()

	db := sqmock.NewMockQuerier(t)
	source := srcmock.NewMockSource(t)

	source.EXPECT().Name().Return("test-source")

	db.EXPECT().GetSourceRef(mock.Anything, mock.Anything).Return(nil, pgx.ErrNoRows)

	worker := &UploadAttestationWorker{
		db:        db,
		source:    source,
		jobClient: &stubJobClient{},
		log:       logrus.NewEntry(logrus.New()),
	}

	job := makeUploadJob()
	err := worker.Work(ctx, job)
	require.Error(t, err)
	db.AssertNotCalled(t, "UpdateWorkloadStateByImage", mock.Anything, mock.Anything)
}
