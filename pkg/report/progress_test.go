package report

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestProgressTracker(t *testing.T) {
	var removedKey string
	var removedVal int
	tracker := NewProgressTracker(
		OnRemove(func(k string, v int) {
			removedKey, removedVal = k, v
		}),
	)

	tracker.Add("a", 1337)
	assert.Equal(t, []int{1337}, tracker.InProgressSnapshot())

	tracker.Remove("a")
	assert.Equal(t, "a", removedKey)
	assert.Equal(t, 1337, removedVal)
	assert.Equal(t, []int{}, tracker.InProgressSnapshot())
}

func TestProgressTrackerDaemon(t *testing.T) {
	var called int
	tracker := NewProgressTracker(
		WithPeriodicInProgressSnapshot[string](context.TODO(), 1*time.Millisecond,
			func([]int) { called++ },
		),
	)
	time.Sleep(10 * time.Millisecond)
	tracker.Stop()
	time.Sleep(2 * time.Millisecond)
	assert.Equal(t, 10, called)
}

func TestProgressTrackerOnStop(t *testing.T) {
	ch := make(chan int)
	tracker := NewProgressTracker(
		OnRemove(func(_ string, v int) {
			ch <- v
		}),
		OnStop[string, int](func() {
			close(ch)
		}),
	)
	go func() {
		tracker.Add("a", 1337)
		tracker.Remove("a")
		tracker.Stop()
	}()
	var values []int
	for val := range ch {
		values = append(values, val)
	}
	assert.Equal(t, []int{1337}, values)
}

func TestProgressTrackerMultiCallbacks(t *testing.T) {
	var count int
	tracker := NewProgressTracker(
		OnAdd(func(string, int) {
			count = 123
		}),
		OnAdd(func(string, int) {
			count *= 2
		}),
	)
	tracker.Add("", 0)
	assert.Equal(t, 246, count)
}
