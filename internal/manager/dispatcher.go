package manager

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
)

type Dispatcher[T any] struct {
	sem                chan struct{} // semaphore
	queue              chan T
	worker             Worker[T]
	wg                 sync.WaitGroup
	postProcessingHook func(ctx context.Context, obj T) error
}

type Worker[T any] func(ctx context.Context, item T) error

func NewDispatcher[T any](worker Worker[T], queue chan T, maxWorkers int) *Dispatcher[T] {
	return &Dispatcher[T]{
		// Restrict the number of goroutine using buffered channel (as counting semaphore)
		sem:    make(chan struct{}, maxWorkers),
		queue:  queue,
		worker: worker,
	}
}

func (d *Dispatcher[T]) Start(ctx context.Context) {
	d.wg.Add(1)
	go d.run(ctx)
}

// Wait blocks until the dispatcher stops.
func (d *Dispatcher[T]) Wait() {
	d.wg.Wait()
}

// Add enqueues an object into the queue.
// If the number of enqueued jobs has already reached its maximum size,
// this will block until the other jobs has finished and the queue has space to accept a new object.
func (d *Dispatcher[T]) Add(obj T) {
	d.queue <- obj
}

func (d *Dispatcher[T]) stop() {
	d.wg.Done()
}

func (d *Dispatcher[T]) run(ctx context.Context) {
	var wg sync.WaitGroup
Loop:
	for {
		select {
		case <-ctx.Done():
			// block until all the jobs finishes
			wg.Wait()
			break Loop
		case obj := <-d.queue:
			// Increment the waitgroup
			wg.Add(1)
			// Decrement a semaphore count
			d.sem <- struct{}{}
			go func(obj T) {
				defer wg.Done()
				// increment the semaphore count after worker is done
				defer func() { <-d.sem }()
				err := d.worker(ctx, obj)
				// TODO: handle with result channel or callback
				if err != nil {
					logrus.Error("Failed to process workload")
				}
				if d.postProcessingHook != nil {
					if err := d.postProcessingHook(ctx, obj); err != nil {
						logrus.Error("Failed to run post process workload hook")
					}
				}
			}(obj)
		}
	}
	d.stop()
}
