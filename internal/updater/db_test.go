package updater

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
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

func TestSyncImageDBErrorInHandleErrorIsReturned(t *testing.T) {
	t.Parallel()

	querier := new(mocksql.MockQuerier)
	ctx := NewDbContext(context.Background(), querier, logrus.NewEntry(logrus.StandardLogger()))

	srcErr := errors.New("source unavailable")
	dbErr := errors.New("db connection lost")

	querier.EXPECT().
		UpdateImageSyncStatus(mock.Anything, mock.Anything).
		Return(dbErr).
		Once()

	err := SyncImage(ctx, "image-a", "v1", "dependencytrack", func(context.Context) error {
		return srcErr
	})

	require.ErrorIs(t, err, dbErr)
	querier.AssertExpectations(t)
}

func TestSyncImageExpiredContextSchedulesResync(t *testing.T) {
	for _, name := range []string{"deadline", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			querier := new(mocksql.MockQuerier)
			querier.Test(t)
			ctx := NewDbContext(t.Context(), querier, logrus.NewEntry(logrus.StandardLogger()))
			var cancel context.CancelFunc
			if name == "deadline" {
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer cancel()
			srcErr := ctx.Err()
			liveContext := mock.MatchedBy(func(ctx context.Context) bool {
				_, bounded := ctx.Deadline()
				return ctx.Err() == nil && bounded
			})

			querier.EXPECT().
				UpdateImageSyncStatus(liveContext, dbsql.UpdateImageSyncStatusParams{
					ImageName:  "image-a",
					ImageTag:   "v1",
					StatusCode: SyncErrorStatusCodeGenericError,
					Reason:     srcErr.Error(),
					Source:     "dependencytrack",
				}).
				Return(nil).
				Once()
			querier.EXPECT().
				UpdateImageState(liveContext, mock.MatchedBy(func(arg dbsql.UpdateImageStateParams) bool {
					return arg.Name == "image-a" && arg.Tag == "v1" && arg.State == dbsql.ImageStateResync && arg.ReadyForResyncAt.Valid
				})).
				Return(int64(1), nil).
				Once()

			require.NoError(t, SyncImage(ctx, "image-a", "v1", "dependencytrack", func(fetchCtx context.Context) error {
				require.ErrorIs(t, fetchCtx.Err(), srcErr)
				return fetchCtx.Err()
			}))
			querier.AssertExpectations(t)
		})
	}
}

func TestSyncImageRecoveryIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		querier := new(mocksql.MockQuerier)
		ctx := NewDbContext(t.Context(), querier, logrus.NewEntry(logrus.StandardLogger()))
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		querier.EXPECT().
			UpdateImageSyncStatus(mock.Anything, mock.Anything).
			RunAndReturn(func(recoveryCtx context.Context, _ dbsql.UpdateImageSyncStatusParams) error {
				require.NoError(t, recoveryCtx.Err(), "recovery must start with a live context")
				<-recoveryCtx.Done()
				return recoveryCtx.Err()
			}).
			Once()

		err := SyncImage(ctx, "image-a", "v1", "dependencytrack", func(ctx context.Context) error {
			return ctx.Err()
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		querier.AssertExpectations(t)
	})
}
