package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/nais/v13s/internal/updater"
	"github.com/stretchr/testify/assert"
)

func TestMarkImagesAsUnused(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("image used by workload should not be marked as unused", func(t *testing.T) {
		createTestdata(t, db, "testimage1", "v1", true)

		err = db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time: time.Now().Add(-updater.MarkAsUntrackedAge),
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage1",
			Tag:  "v1",
		})
		assert.NoError(t, err)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("image with resync state should not be marked as unused", func(t *testing.T) {
		createTestdata(t, db, "testimage2", "v1", true)

		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})
		assert.NoError(t, err)

		err = db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  image.Name,
			Tag:   image.Tag,
			State: sql.ImageStateResync,
		})
		assert.NoError(t, err)

		err = db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time: time.Now().Add(-updater.MarkAsUntrackedAge),
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)

		image, err = db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})
		assert.NoError(t, err)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("image without workload should be marked as unused", func(t *testing.T) {

		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage",
			Tag:      "old",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		err = db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(1 * time.Minute),
					Valid: true,
				},
				ExcludedStates: []sql.ImageState{
					sql.ImageStateResync,
					sql.ImageStateFailed,
				},
			})
		assert.NoError(t, err)
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage",
			Tag:  "old",
		})

		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateUnused, image.State)
	})

}

func createTestdata(t *testing.T, db sql.Querier, image_name, image_tag string, createWorkload bool) {
	ctx := context.Background()
	err := db.CreateImage(ctx, sql.CreateImageParams{
		Name:     image_name,
		Tag:      image_tag,
		Metadata: map[string]string{},
	})
	assert.NoError(t, err)

	if !createWorkload {
		return
	}
	_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         image_name,
		WorkloadType: "application",
		Namespace:    "testnamespace1",
		Cluster:      "testcluster1",
		ImageName:    image_name,
		ImageTag:     image_tag,
	})
	assert.NoError(t, err)
}
