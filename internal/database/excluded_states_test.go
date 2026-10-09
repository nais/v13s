package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkImagesForResync_SkipsExcludedStates(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	names := []string{"resync-updated", "resync-failed", "resync-untracked"}
	for name, state := range map[string]sql.ImageState{
		"resync-updated":   sql.ImageStateUpdated,
		"resync-failed":    sql.ImageStateFailed,
		"resync-untracked": sql.ImageStateUntracked,
	} {
		createTestdata(t, db, name, "v1", true)
		_, err := pool.Exec(ctx, `UPDATE images SET state = $2 WHERE name = $1`, name, state)
		require.NoError(t, err)
	}

	require.NoError(t, db.MarkImagesForResync(ctx, sql.MarkImagesForResyncParams{
		ThresholdTime:  pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
		ExcludedStates: []sql.ImageState{sql.ImageStateResync, sql.ImageStateUntracked, sql.ImageStateFailed},
	}))

	got := map[string]sql.ImageState{}
	for _, n := range names {
		img, err := db.GetImage(ctx, sql.GetImageParams{Name: n, Tag: "v1"})
		require.NoError(t, err)
		got[n] = img.State
	}
	assert.Equal(t, map[string]sql.ImageState{
		"resync-updated":   sql.ImageStateResync,
		"resync-failed":    sql.ImageStateFailed,
		"resync-untracked": sql.ImageStateUntracked,
	}, got)
}
