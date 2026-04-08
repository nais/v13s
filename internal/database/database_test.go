package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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

		affectedRows, err := db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(-updater.ImageMarkAge),
					Valid: true,
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
		assert.Equal(t, int64(0), affectedRows)
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

		affectedRows, err := db.MarkUnusedImages(ctx,
			sql.MarkUnusedImagesParams{
				ThresholdTime: pgtype.Timestamptz{
					Time:  time.Now().Add(-updater.ImageMarkAge),
					Valid: true,
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
		assert.Equal(t, int64(0), affectedRows)
		assert.NotEqual(t, sql.ImageStateUnused, image.State)
	})

	t.Run("image without workload should be marked as unused", func(t *testing.T) {
		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     "testimage",
			Tag:      "old",
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		affectedRows, err := db.MarkUnusedImages(ctx,
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
		assert.Equal(t, int64(1), affectedRows)
		assert.Equal(t, sql.ImageStateUnused, image.State)
	})
}

func TestDeleteUnusedSourceRefs(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	imageName := "testimage-srcref"
	imageTagUnused := "unused"
	imageTagUsed := "used"

	assert.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: imageName, Tag: imageTagUnused, Metadata: map[string]string{}}))
	assert.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: imageName, Tag: imageTagUsed, Metadata: map[string]string{}}))

	_, err = db.CreateWorkload(ctx, sql.CreateWorkloadParams{
		Name:         "wl1",
		WorkloadType: "application",
		Namespace:    "test",
		Cluster:      "test",
		ImageName:    imageName,
		ImageTag:     imageTagUsed,
	})
	assert.NoError(t, err)

	srcUnusedID := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	srcUsedID := pgtype.UUID{Bytes: uuid.New(), Valid: true}

	assert.NoError(t, db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID:   srcUnusedID,
		SourceType: "dependencytrack",
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
	}))

	assert.NoError(t, db.CreateSourceRef(ctx, sql.CreateSourceRefParams{
		SourceID:   srcUsedID,
		SourceType: "dependencytrack",
		ImageName:  imageName,
		ImageTag:   imageTagUsed,
	}))

	rows, err := db.ListUnusedSourceRefs(ctx, &imageName)
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, imageTagUnused, rows[0].ImageTag)

	err = db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)

	err = db.DeleteSourceRef(ctx, sql.DeleteSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUnused,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)

	rowsAfter, err := db.ListUnusedSourceRefs(ctx, &imageName)
	assert.NoError(t, err)
	assert.Len(t, rowsAfter, 0)

	srcUsed, err := db.GetSourceRef(ctx, sql.GetSourceRefParams{
		ImageName:  imageName,
		ImageTag:   imageTagUsed,
		SourceType: "dependencytrack",
	})
	assert.NoError(t, err)
	assert.Equal(t, imageTagUsed, srcUsed.ImageTag)
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

func TestMarkWorkloadsWithUntrackedImages(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("workload in processing state with untracked image should be marked as failed", func(t *testing.T) {
		imageName := "untracked-image-1"
		imageTag := "v1"

		// Create image
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Create workload in processing state
		_, err = db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-processing",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)

		// Mark image as untracked
		err = db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateUntracked,
		})
		assert.NoError(t, err)

		// Run MarkWorkloadsWithUntrackedImages
		affectedRows, err := db.MarkWorkloadsWithUntrackedImages(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), affectedRows)

		// Verify workload state is now failed
		workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         "workload-processing",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.WorkloadStateFailed, workload.State)
	})

	t.Run("workload NOT in processing state should NOT be affected", func(t *testing.T) {
		imageName := "untracked-image-2"
		imageTag := "v1"

		// Create image
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Create workload and set to updated state
		id, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-updated",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)

		err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			ID:    id,
			State: sql.WorkloadStateUpdated,
		})
		assert.NoError(t, err)

		// Mark image as untracked
		err = db.UpdateImageState(ctx, sql.UpdateImageStateParams{
			Name:  imageName,
			Tag:   imageTag,
			State: sql.ImageStateUntracked,
		})
		assert.NoError(t, err)

		// Run MarkWorkloadsWithUntrackedImages
		affectedRows, err := db.MarkWorkloadsWithUntrackedImages(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), affectedRows)

		// Verify workload state is still updated
		workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         "workload-updated",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.WorkloadStateUpdated, workload.State)
	})
}

func TestInitializeWorkload_UnrecoverableState(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)

	err := db.ResetDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unrecoverable workload should NOT be reset when image is the same", func(t *testing.T) {
		imageName := "unrecoverable-image-1"
		imageTag := "v1"

		// Create image
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Create workload
		id, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-unrecoverable",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)

		// Set workload to unrecoverable
		err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			ID:    id,
			State: sql.WorkloadStateUnrecoverable,
		})
		assert.NoError(t, err)

		// Try to initialize again with same image - should NOT reset (returns no rows)
		_, err = db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-unrecoverable",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		// Should return ErrNoRows because the workload was not updated
		assert.Error(t, err)

		// Verify workload state is still unrecoverable
		workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         "workload-unrecoverable",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.WorkloadStateUnrecoverable, workload.State)
	})

	t.Run("unrecoverable workload SHOULD be reset when image changes", func(t *testing.T) {
		imageName := "unrecoverable-image-2"
		imageTag := "v1"
		newImageTag := "v2"

		// Create images
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		err = db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      newImageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Create workload
		id, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-unrecoverable-new-image",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)

		// Set workload to unrecoverable
		err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			ID:    id,
			State: sql.WorkloadStateUnrecoverable,
		})
		assert.NoError(t, err)

		// Initialize with NEW image tag - should reset
		newId, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-unrecoverable-new-image",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     newImageTag,
		})
		assert.NoError(t, err)
		assert.Equal(t, id, newId) // Same workload ID

		// Verify workload state is now processing with new image
		workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         "workload-unrecoverable-new-image",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.WorkloadStateProcessing, workload.State)
		assert.Equal(t, newImageTag, workload.ImageTag)
	})

	t.Run("failed workload SHOULD be reset even with same image", func(t *testing.T) {
		imageName := "failed-image-1"
		imageTag := "v1"

		// Create image
		err := db.CreateImage(ctx, sql.CreateImageParams{
			Name:     imageName,
			Tag:      imageTag,
			Metadata: map[string]string{},
		})
		assert.NoError(t, err)

		// Create workload
		id, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-failed",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)

		// Set workload to failed
		err = db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{
			ID:    id,
			State: sql.WorkloadStateFailed,
		})
		assert.NoError(t, err)

		// Initialize again with same image - should reset because state is failed
		newId, err := db.InitializeWorkload(ctx, sql.InitializeWorkloadParams{
			Name:         "workload-failed",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
			ImageName:    imageName,
			ImageTag:     imageTag,
		})
		assert.NoError(t, err)
		assert.Equal(t, id, newId)

		// Verify workload state is now processing
		workload, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Name:         "workload-failed",
			WorkloadType: "app",
			Namespace:    "test",
			Cluster:      "test",
		})
		assert.NoError(t, err)
		assert.Equal(t, sql.WorkloadStateProcessing, workload.State)
	})
}
