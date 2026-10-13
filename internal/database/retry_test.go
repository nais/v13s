package database

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Nothing listens on port 1, so every attempt fails right away.
const unreachableDSN = "postgres://v13s:v13s@127.0.0.1:1/v13s?sslmode=disable&connect_timeout=1"

func TestSleep(t *testing.T) {
	t.Run("returns after the duration", func(t *testing.T) {
		assert.NoError(t, sleep(context.Background(), time.Millisecond))
	})

	t.Run("returns at once when already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		assert.ErrorIs(t, sleep(ctx, time.Minute), context.Canceled)
		assert.Less(t, time.Since(start), time.Second)
	})

	t.Run("returns when cancelled during the wait", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		assert.ErrorIs(t, sleep(ctx, time.Minute), context.DeadlineExceeded)
		assert.Less(t, time.Since(start), time.Second)
	})
}

func TestNewPoolStopsRetryingWhenCancelled(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)

	for name, migrate := range map[string]bool{"migration": true, "connection": false} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			start := time.Now()
			pool, err := NewPool(ctx, unreachableDSN, log, migrate)
			require.Nil(t, pool)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Less(t, time.Since(start), 3*time.Second)
		})
	}
}
