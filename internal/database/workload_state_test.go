package database_test

import (
	"context"
	"testing"

	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateWorkloadStateForImage_IgnoresWorkloadMovedToAnotherImage(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	createTestdata(t, db, "moved-image", "v1", false)
	createTestdata(t, db, "moved-image", "v2", false)
	params := sql.UpsertWorkloadParams{Name: "wl", WorkloadType: "app", Namespace: "ns", Cluster: "cluster", ImageName: "moved-image", ImageTag: "v1"}
	_, err := db.UpsertWorkload(ctx, params)
	require.NoError(t, err)
	wl, err := db.GetWorkload(ctx, sql.GetWorkloadParams{Name: "wl", WorkloadType: "app", Namespace: "ns", Cluster: "cluster"})
	require.NoError(t, err)

	params.ImageTag = "v2"
	_, err = db.UpsertWorkload(ctx, params)
	require.NoError(t, err)
	require.NoError(t, db.UpdateWorkloadState(ctx, sql.UpdateWorkloadStateParams{State: sql.WorkloadStateUpdated, ID: wl.ID}))

	update := func(tag string) sql.WorkloadState {
		require.NoError(t, db.UpdateWorkloadStateForImage(ctx, sql.UpdateWorkloadStateForImageParams{
			State: sql.WorkloadStateNoAttestation, ID: wl.ID, ImageName: "moved-image", ImageTag: tag,
		}))
		got, err := db.GetWorkload(ctx, sql.GetWorkloadParams{Name: "wl", WorkloadType: "app", Namespace: "ns", Cluster: "cluster"})
		require.NoError(t, err)
		return got.State
	}

	assert.Equal(t, sql.WorkloadStateUpdated, update("v1"), "a result for the previous image must not change the workload")
	assert.Equal(t, sql.WorkloadStateNoAttestation, update("v2"))
}
