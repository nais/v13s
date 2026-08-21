package updater

import (
	"context"
	"errors"
	"testing"
	"time"

	dbsql "github.com/nais/v13s/internal/database/sql"
	mocksql "github.com/nais/v13s/internal/mocks/Querier"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSyncImageRecoverableErrorSchedulesResync(t *testing.T) {
	t.Parallel()

	querier := new(mocksql.MockQuerier)
	ctx := NewDbContext(context.Background(), querier, logrus.NewEntry(logrus.StandardLogger()))

	errBoom := errors.New("source unavailable")
	now := time.Now()

	querier.EXPECT().
		UpdateImageSyncStatus(mock.Anything, dbsql.UpdateImageSyncStatusParams{
			ImageName:  "image-a",
			ImageTag:   "v1",
			StatusCode: SyncErrorStatusCodeGenericError,
			Reason:     errBoom.Error(),
			Source:     "dependencytrack",
		}).
		Return(nil).
		Once()

	querier.EXPECT().
		UpdateImageState(mock.Anything, mock.MatchedBy(func(arg dbsql.UpdateImageStateParams) bool {
			if arg.Name != "image-a" || arg.Tag != "v1" || arg.State != dbsql.ImageStateResync {
				return false
			}
			if !arg.ReadyForResyncAt.Valid {
				return false
			}
			earliest := now.Add(RecoverableResyncCooldown - time.Second)
			latest := now.Add(RecoverableResyncCooldown + time.Second)
			return arg.ReadyForResyncAt.Time.After(earliest) && arg.ReadyForResyncAt.Time.Before(latest)
		})).
		Return(int64(1), nil).
		Once()

	err := SyncImage(ctx, "image-a", "v1", "dependencytrack", func(context.Context) error {
		return errBoom
	})

	require.NoError(t, err)
	querier.AssertExpectations(t)
}
