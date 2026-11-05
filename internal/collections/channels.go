package collections

import "context"

// ReadChannel reads from a channel until it is closed, size == chunkSize or the context is done
func ReadChannel[T any](ctx context.Context, ch chan T, chunkSize int) ([]T, error) {
	elements := make([]T, 0)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case e, more := <-ch:
			if !more {
				return elements, nil
			}

			elements = append(elements, e)
			if len(elements) == chunkSize {
				return elements, nil
			}
		}
	}
}
