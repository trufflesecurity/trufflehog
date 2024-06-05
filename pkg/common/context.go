package common

import "context"

func IsDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// CancellableWrite blocks on writing the item to the channel but can be
// cancelled by the context. If both the context is cancelled and the channel
// write would succeed, either operation will be performed randomly.
func CancellableWrite[T any](ctx context.Context, ch chan<- T, item T) error {
	select {
	case <-ctx.Done(): // priority to context cancellation
		return ctx.Err()
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- item:
			return nil
		}
	}
}

// CancellableRecv blocks on receiving an item from the channel but can be
// cancelled by the context. If both the context is cancelled and the channel
// read would succeed, either operation will be performed randomly.
func CancellableRecv[T any](ctx context.Context, ch <-chan T) (T, error) {
	var zero T // zero value of type T

	select {
	case <-ctx.Done(): // priority to context cancellation
		return zero, ctx.Err()
	default:
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case item := <-ch:
			return item, nil
		}
	}
}
