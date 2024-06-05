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
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Once()
	mockMetrics.On("RecordChannelCap", bufferCap).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)
	assert.Equal(t, bufferCap, cap(oc.ch))

	oc.Send(context.Background(), 1)

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecv(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordConsumeDuration", mock.Anything).Once() // For the send
	mockMetrics.On("RecordProduceDuration", mock.Anything).Once()
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Twice() // For the send and recv
	mockMetrics.On("RecordChannelCap", bufferCap).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)
	assert.Equal(t, bufferCap, cap(oc.ch))

	go func() {
		oc.Send(context.Background(), 1)
	}()

	time.Sleep(100 * time.Millisecond) // Ensure Send happens before Recv

	oc.Recv(context.Background())

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecordChannelCapacity(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordChannelCap", bufferCap).Twice()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)

	oc.RecordChannelCapacity()

	mockMetrics.AssertExpectations(t)
}

func TestObservableChanRecordChannelLen(t *testing.T) {
	t.Parallel()

	mockMetrics := new(MockMetricsCollector)
	bufferCap := 10

	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Once()
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
	mockMetrics.On("RecordChannelLen", mock.AnythingOfType("int")).Once()

	ch := make(chan int, bufferCap)
	oc := NewObservableChan(ch, mockMetrics)

	oc.Close()

	mockMetrics.AssertExpectations(t)
}
