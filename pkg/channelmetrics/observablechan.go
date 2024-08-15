// Package channelmetrics provides a flexible way to wrap Go channels with
// additional metrics collection capabilities. This allows for monitoring
// and tracking of channel usage and performance using different metrics backends.
package channelmetrics

import (
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// MetricsCollector is an interface for collecting metrics. Implementations
// of this interface can be used to record various channel metrics.
type MetricsCollector interface {
	RecordProduceDuration(duration time.Duration)
	RecordConsumeDuration(duration time.Duration)
	RecordChannelLen(size int)
	RecordChannelCap(capacity int)
}

// ObservableChan wraps a Go channel and collects metrics about its usage.
// It supports any type of channel and records metrics using a provided
// MetricsCollector implementation.
type ObservableChan[T any] struct {
	ch      chan T
	metrics MetricsCollector
}

// NewObservableChan creates a new ObservableChan wrapping the provided channel.
// It records the channel's capacity immediately and sets up metrics collection
// using the provided MetricsCollector and channel name. The chanName is used to
// distinguish between metrics for different channels by incorporating it into
// the metric names.
func NewObservableChan[T any](ch chan T, metrics MetricsCollector) *ObservableChan[T] {
	if metrics == nil {
		metrics = noopCollector{}
	}
	oChan := &ObservableChan[T]{
		ch:      ch,
		metrics: metrics,
	}
	oChan.RecordChannelCapacity()
	// Record the current length of the channel.
	// Note: The channel is likely empty, but it may contain items if it
	// was pre-existing.
	oChan.RecordChannelLen()
	return oChan
}

// Close closes the channel and records the current size of the channel buffer.
func (oc *ObservableChan[T]) Close() {
	close(oc.ch)
	oc.RecordChannelLen()
}

// Send sends an item into the channel and records the duration taken to do so.
// It also updates the current size of the channel buffer. This method blocks
// until the item is sent.
func (oc *ObservableChan[T]) Send(item T) { _ = oc.SendCtx(context.Background(), item) }

// SendCtx sends an item into the channel with context and records the duration
// taken to do so. It also updates the current size of the channel buffer and
// supports context cancellation.
func (oc *ObservableChan[T]) SendCtx(ctx context.Context, item T) error {
	defer func(start time.Time) {
		oc.metrics.RecordProduceDuration(time.Since(start))
		oc.RecordChannelLen()
	}(time.Now())

	return common.CancellableWrite(ctx, oc.ch, item)
}

// Recv receives an item from the channel and records the duration taken to do
// so. It also updates the current size of the channel buffer. This method
// blocks until an item is available.
func (oc *ObservableChan[T]) Recv() T {
	v, _ := oc.RecvCtx(context.Background())
	return v
}

// RecvCtx receives an item from the channel with context and records the
// duration taken to do so. It also updates the current size of the channel
// buffer and supports context cancellation. If an error occurs, it logs the
// error.
func (oc *ObservableChan[T]) RecvCtx(ctx context.Context) (T, error) {
	defer func(start time.Time) {
		oc.metrics.RecordConsumeDuration(time.Since(start))
		oc.RecordChannelLen()
	}(time.Now())

	return common.CancellableRead(ctx, oc.ch)
}

// RecordChannelCapacity records the capacity of the channel buffer.
func (oc *ObservableChan[T]) RecordChannelCapacity() { oc.metrics.RecordChannelCap(cap(oc.ch)) }

// RecordChannelLen records the current size of the channel buffer.
func (oc *ObservableChan[T]) RecordChannelLen() { oc.metrics.RecordChannelLen(len(oc.ch)) }
