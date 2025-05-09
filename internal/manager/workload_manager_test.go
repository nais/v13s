package manager

import (
	"context"
	"fmt"
	"github.com/nais/v13s/internal/attestation"
	"github.com/nais/v13s/internal/database/sql"
	"github.com/nais/v13s/internal/kubernetes"
	"github.com/nais/v13s/internal/model"
	"github.com/nais/v13s/internal/sources"
	"github.com/nais/v13s/internal/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"sync"
	"testing"
)

// TODO: add more tests especially for the states and error handling
func TestWorkloadManager(t *testing.T) {
	ctx := context.Background()

	pool := test.GetPool(ctx, t, true)
	defer pool.Close()
	db := sql.New(pool)
	err := db.ResetDatabase(ctx)
	assert.NoError(t, err)

	source := sources.NewMockSource(t)

	queue := &kubernetes.WorkloadEventQueue{
		Updated: make(chan *model.Workload, 10),
		Deleted: make(chan *model.Workload, 10),
	}
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	verifier := attestation.NewMockVerifier(t)
	mgr := NewWorkloadManager(pool, verifier, source, queue, logrus.WithField("subsystem", "test"))
	t.Run("should only update the same workload from a goroutine/pod at a time", func(t *testing.T) {
		numWorkloads := 10
		verifier.EXPECT().GetAttestation(mock.Anything, mock.Anything).Return(nil, nil).Times(2)
		mgr.Start(ctx)
		var wg sync.WaitGroup
		start := make(chan struct{}) // barrier to synchronize goroutines

		var processingWg sync.WaitGroup
		processingWg.Add(numWorkloads)

		mgr.addDispatcher.postProcessingHook = func(ctx context.Context, obj *model.Workload) error {
			processingWg.Done()
			return nil
		}

		for i := 0; i < numWorkloads; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start // wait for the barrier
				queue.Updated <- workload("test", 0)
			}(i)
		}

		close(start)
		wg.Wait()
		processingWg.Wait()
		err = mgr.AddWorkload(ctx, workload("test", 100))
		assert.NoError(t, err)
		w, err := db.GetWorkload(ctx, sql.GetWorkloadParams{
			Cluster:      "test",
			Namespace:    "test",
			Name:         "test",
			WorkloadType: "app",
		})
		assert.NoError(t, err)
		assert.Equal(t, "100", w.ImageTag)
	})
}

func workload(name string, imageTag int) *model.Workload {
	return &model.Workload{
		Name:      name,
		Namespace: "test",
		Cluster:   "test",
		Type:      model.WorkloadTypeApp,
		ImageName: "test-image",
		ImageTag:  fmt.Sprintf("%d", imageTag),
	}
}
