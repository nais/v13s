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
		verifier.EXPECT().GetAttestation(mock.Anything, mock.Anything).Return(nil, nil).Times(1)

		mgr.Start(ctx)
		var wg sync.WaitGroup
		start := make(chan struct{}) // barrier to synchronize goroutines

		numWorkloads := 10
		mgr.addDispatcher.processingWg.Add(numWorkloads)
		for i := 0; i < numWorkloads; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start // wait for the barrier
				queue.Updated <- workload("test", i)
			}(i)
		}

		close(start)
		wg.Wait()
		mgr.addDispatcher.processingWg.Wait()
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
