package collections

import (
	"context"
	"time"
)

// ReadChannel reads until the channel closes, chunkSize is reached, maxWait elapses after the first element, or ctx is done.
func ReadChannel[T any](ctx context.Context, ch chan T, chunkSize int, maxWait time.Duration) ([]T, error) {
	elements := make([]T, 0)
	var timer *time.Timer
	var timeout <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return elements, nil
		case e, more := <-ch:
			if !more {
				return elements, nil
			}

			elements = append(elements, e)
			if len(elements) == chunkSize {
				return elements, nil
			}
			if timer == nil {
				timer = time.NewTimer(maxWait)
				timeout = timer.C
			}
		}
	}
}
