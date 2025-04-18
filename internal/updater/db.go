package updater

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
)

const (
	SyncErrorStatusCodeGenericError = "GenericError"
)

type database struct {
	querier sql.Querier
	log     *logrus.Entry
}

type ctxKey int

const dbKey ctxKey = iota

func NewDbContext(ctx context.Context, querier sql.Querier, log *logrus.Entry) context.Context {
	return context.WithValue(ctx, dbKey, &database{
		querier: querier,
		log:     log,
	})
}

// SyncImage runs the provided function and updates the image state in the database based on the result, it should only return an error if the image state update failed.
func SyncImage(ctx context.Context, imageName, imageTag, source string, f func(ctx context.Context) error) error {
	d := db(ctx)
	err := f(ctx)
	if err != nil {
		err = handleError(ctx, imageName, imageTag, source, err)
		if err != nil {
			err = d.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				Name:  imageName,
				Tag:   imageTag,
				State: sql.ImageStateFailed,
			})
			if err != nil {
				d.log.Errorf("failed to update image state: %v", err)
				return fmt.Errorf("updating image state: %w", err)
			}
			return nil
		}
		return nil
	}

	/*err = d.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateUpdated,
	})*/

	return err
}

func db(ctx context.Context) *database {
	return ctx.Value(dbKey).(*database)
}

func handleError(ctx context.Context, imageName, imageTag string, source string, err error) error {
	d := db(ctx)
	updateSyncParams := sql.UpdateImageSyncStatusParams{
		ImageName: imageName,
		ImageTag:  imageTag,
		Source:    source,
	}

	if err == nil || errors.Is(err, sources.ErrNoProject) || errors.Is(err, sources.ErrNoMetrics) {
		return nil
	}

	updateSyncParams.Reason = err.Error()
	updateSyncParams.StatusCode = SyncErrorStatusCodeGenericError
	d.log.Debugf("orginal error status: %v", err)

	if insertErr := d.querier.UpdateImageSyncStatus(ctx, updateSyncParams); insertErr != nil {
		d.log.Errorf("failed to update image sync status: %v", insertErr)
		return fmt.Errorf("updating image sync status: %w", insertErr)
	}

	return err
}
