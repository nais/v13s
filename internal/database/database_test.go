package database_test

import (
	"context"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDatabaseQueries(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("TestMarkUnusedImages", func(t *testing.T) {
		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage1",
			Tag:      "v1",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
			Name:         "testworkload1",
			WorkloadType: "application",
			Namespace:    "testnamspace1",
			Cluster:      "testcluster1",
			ImageName:    "testimage1",
			ImageTag:     "v1",
		})
		assert.NoError(t, err)

		err = db.MarkUnusedImages(ctx,
			[]sql.ImageState{
				sql.ImageStateResync,
				sql.ImageStateFailed,
			})
		assert.NoError(t, err)
		image, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage1",
			Tag:  "v1",
		})
		assert.NoError(t, err)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("Resync state is not changed after UpdateImageState", func(t *testing.T) {

		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage2",
			Tag:      "v1",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		image2, err := db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})
		assert.NoError(t, err)

		_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
			Name:         "testworkload2",
			WorkloadType: "application",
			Namespace:    "testnamspace1",
			Cluster:      "testcluster1",
			ImageName:    "testimage2",
			ImageTag:     "v1",
		})
		assert.NoError(t, err)

		db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  image2.Name,
			Tag:   image2.Tag,
			State: sql.ImageStateResync,
		})

		image2, err = db.GetImage(ctx, sql.GetImageParams{
			Name: "testimage2",
			Tag:  "v1",
		})

		err = db.MarkUnusedImages(ctx,
			[]sql.ImageState{
				sql.ImageStateResync,
				sql.ImageStateFailed,
			})
		assert.NoError(t, err)

		assert.NoError(t, err)
		assert.Equal(t, sql.ImageStateResync, image2.State)

	})

	t.Run("Image without workload", func(t *testing.T) {

		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage",
			Tag:      "old",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		err = db.MarkUnusedImages(ctx,
			[]sql.ImageState{
				sql.ImageStateResync,
				sql.ImageStateFailed,
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
