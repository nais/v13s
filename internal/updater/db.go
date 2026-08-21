package updater

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sirupsen/logrus"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
)

const (
	SyncErrorStatusCodeGenericError = "GenericError"
	RecoverableResyncCooldown       = 15 * time.Minute
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

// SyncImage runs the provided function and updates the image state in the database based on the result.
// It returns an error only if a DB state update fails.
// Recoverable source errors schedule the image for resync with cooldown and return nil.
func SyncImage(ctx context.Context, imageName, imageTag, source string, f func(ctx context.Context) error) error {
	d := db(ctx)
	srcErr := f(ctx)
	if srcErr != nil {
		handleErr := handleError(ctx, imageName, imageTag, source, srcErr)
		switch {
		case handleErr == nil:
			// terminal: already handled (ErrNoProject, ErrNoMetrics) — state written inside handleError
			return nil
		case !errors.Is(handleErr, srcErr):
			// handleError itself failed (DB error) — propagate, do not schedule resync
			return handleErr
		default:
			// recoverable source error: handleErr == srcErr, sync status persisted — schedule resync
			cooldownUntil := time.Now().Add(RecoverableResyncCooldown)
			n, updateErr := d.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
				Name:  imageName,
				Tag:   imageTag,
				State: sql.ImageStateResync,
				ReadyForResyncAt: pgtype.Timestamptz{
					Time:  cooldownUntil,
					Valid: true,
				},
			})
			if updateErr != nil {
				d.log.Errorf("failed to update image state: %v", updateErr)
				return fmt.Errorf("updating image state: %w", updateErr)
			}
			if n == 0 {
				d.log.Warnf("UpdateImageState matched no rows for image %s:%s, image may already be gone", imageName, imageTag)
			}
			return nil
		}
	}

	/*err = d.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
		Name:  imageName,
		Tag:   imageTag,
		State: sql.ImageStateUpdated,
	})*/

	return nil
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

	if err == nil || errors.Is(err, sources.ErrNoMetrics) {
		return nil
	}

	if errors.Is(err, sources.ErrNoProject) {
		if dbErr := d.querier.UpdateWorkloadStateByImage(ctx, sql.UpdateWorkloadStateByImageParams{
			ImageName: imageName,
			ImageTag:  imageTag,
			State:     sql.WorkloadStateNoAttestation,
		}); dbErr != nil {
			d.log.Errorf("failed to update workload state to no_attestation: %v", dbErr)
			return fmt.Errorf("updating workload state: %w", dbErr)
		}
		n, dbErr := d.querier.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateFailed,
		})
		if dbErr != nil {
			d.log.Errorf("failed to update image state to failed: %v", dbErr)
			return fmt.Errorf("updating image state: %w", dbErr)
		}
		if n == 0 {
			d.log.Warnf("UpdateImageState matched no rows for image %s:%s, image may already be gone", imageName, imageTag)
		}
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
