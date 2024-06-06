package channelmetrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type MockMetricsCollector struct{ mock.Mock }

func (m *MockMetricsCollector) RecordProduceDuration(duration time.Duration) { m.Called(duration) }

func (m *MockMetricsCollector) RecordConsumeDuration(duration time.Duration) { m.Called(duration) }

func (m *MockMetricsCollector) RecordChannelLen(size int) { m.Called(size) }

func (m *MockMetricsCollector) RecordChannelCap(capacity int) { m.Called(capacity) }

func TestObservableChanSend(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordProduceDuration", mock.Anything).Once()
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Twice()
	mockMetrics.On("RecordChannelCap", bufferCap).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)
	assert.Equal(t, bufferCap, cap(oc.ch))

	err := oc.SendCtx(context.Background(), 1)
	assert.NoError(t, err)

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecv(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordConsumeDuration", mock.Anything).Once() // For the send
	mockMetrics.On("RecordProduceDuration", mock.Anything).Once()
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Times(3) // For the send and recv
	mockMetrics.On("RecordChannelCap", bufferCap).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)
	assert.Equal(t, bufferCap, cap(oc.ch))

	go func() {
		err := oc.SendCtx(context.Background(), 1)
		assert.NoError(t, err)
	}()

	time.Sleep(100 * time.Millisecond) // Ensure Send happens before Recv

	_, err := oc.RecvCtx(context.Background())
	assert.NoError(t, err)

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecordChannelCapacity(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordChannelCap", bufferCap).Twice()
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)

	oc.RecordChannelCapacity()

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecordChannelLen(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Twice()
	mockMetrics.On("RecordChannelCap", bufferCap).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)

	oc.RecordChannelLen()

	mockMetrics.AssertExpectations(t)
}

func TestObservableChan_Close(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 1

	mockMetrics.On("RecordChannelCap", bufferCap).Once()
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Twice()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)

	oc.Close()

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanClosed(t *testing.T) {
	t.Parallel()

	ch := make(chan int)
	close(ch)
	oc := NewObservableChan(ch, nil)

	ctx, cancel := context.WithCancel(context.Background())
	// Closed channel should return with an error.
	v, err := oc.RecvCtx(ctx)
	assert.Error(t, err)
	assert.Equal(t, 0, v)

	// Cancelled context should also return with an error.
	cancel()
	_, err = oc.RecvCtx(ctx)
	assert.Error(t, err)
}
