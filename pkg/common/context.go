package common

import "context"

// ChannelClosedErr indicates that a read was performed from a closed channel.
type ChannelClosedErr struct{}

func (ChannelClosedErr) Error() string { return "channel is closed" }

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
// write would succeed, either operation will be performed randomly, however
// priority is given to context cancellation.
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

// CancellableRead blocks on receiving an item from the channel but can be
// cancelled by the context. If the channel is closed, a ChannelClosedErr is
// returned. If both the context is cancelled and the channel read would
// succeed, either operation will be performed randomly, however priority is
// given to context cancellation.
func CancellableRead[T any](ctx context.Context, ch <-chan T) (T, error) {
	var zero T // zero value of type T

	select {
	case <-ctx.Done(): // priority to context cancellation
		return zero, ctx.Err()
	default:
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case item, ok := <-ch:
			if !ok {
				return item, ChannelClosedErr{}
			}
			return item, nil
		}
	}
}
