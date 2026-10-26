//go:build integration_test

package updater

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nais/v13s/internal/config"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type blockingSource struct{ sources.Source }

func (blockingSource) Name() string { return "blocking" }
func (blockingSource) GetVulnerabilities(ctx context.Context, _, _ string, _ bool) ([]*sources.Vulnerability, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type partlyBlockingSource struct {
	sources.Source
	blockedImage string
}

func (partlyBlockingSource) Name() string { return "partly-blocking" }
func (s partlyBlockingSource) GetVulnerabilities(ctx context.Context, imageName, _ string, _ bool) ([]*sources.Vulnerability, error) {
	if imageName == s.blockedImage {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []*sources.Vulnerability{}, nil
}

func (partlyBlockingSource) MaintainSuppressedVulnerabilities(context.Context, []*sources.SuppressedVulnerability) error {
	return nil
}

func TestResyncImageVulnerabilities_BatchTimeoutKeepsFetchedImages(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	for i := range 3 {
		name := fmt.Sprintf("image-%d", i)
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: name, Tag: "v1", Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = 'resync', ready_for_resync_at = NOW() - INTERVAL '1 minute' WHERE name = $1`, name)
		require.NoError(t, err)
	}

	u := NewUpdater(pool, partlyBlockingSource{blockedImage: "image-0"}, ScheduleConfig{}, logrus.NewEntry(logrus.StandardLogger()), config.KevConfig{}, config.OsvConfig{})
	u.resyncBatchTimeout = 500 * time.Millisecond

	_ = u.ResyncImageVulnerabilities(ctx)

	for _, name := range []string{"image-1", "image-2"} {
		image, err := db.GetImage(ctx, sql.GetImageParams{Name: name, Tag: "v1"})
		require.NoError(t, err)
		require.Equal(t, sql.ImageStateUpdated, image.State, "%s was fetched before the batch timed out and should be stored", name)
	}
}

func TestResyncImageVulnerabilities_BatchTimeoutStopsFetching(t *testing.T) {
	ctx := context.Background()
	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	require.NoError(t, db.ResetDatabase(ctx))

	for i := range 3 {
		name := fmt.Sprintf("image-%d", i)
		require.NoError(t, db.CreateImage(ctx, sql.CreateImageParams{Name: name, Tag: "v1", Metadata: map[string]string{}}))
		_, err := pool.Exec(ctx, `UPDATE images SET state = 'resync', ready_for_resync_at = NOW() - INTERVAL '1 minute' WHERE name = $1`, name)
		require.NoError(t, err)
	}

	u := NewUpdater(pool, blockingSource{}, ScheduleConfig{}, logrus.NewEntry(logrus.StandardLogger()), config.KevConfig{}, config.OsvConfig{})
	u.resyncBatchTimeout = 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = u.ResyncImageVulnerabilities(ctx)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ResyncImageVulnerabilities kept fetching after the batch timeout")
	}
}
