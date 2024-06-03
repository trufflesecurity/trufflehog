package report

import (
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// ProgressTracker is an in-memory, thread-safe object tracker. It can be
// configured with callbacks when an object is added, removed, or the entire
// tracker is stopped.
type ProgressTracker[K comparable, V any] struct {
	mu                 sync.Mutex
	inProgressDaemonWg sync.WaitGroup
	inProgress         map[K]V
	onStop             func()
	onAdd              func(K, V)
	onRemove           func(K, V)
}

type ProgressTrackerOpt[K comparable, V any] func(*ProgressTracker[K, V])

func OnAdd[K comparable, V any](
	f func(K, V),
) ProgressTrackerOpt[K, V] {
	return func(pt *ProgressTracker[K, V]) {
		pt.onAdd = composeKV(pt.onAdd, f)
	}
}

func OnRemove[K comparable, V any](
	f func(K, V),
) ProgressTrackerOpt[K, V] {
	return func(pt *ProgressTracker[K, V]) {
		pt.onRemove = composeKV(pt.onRemove, f)
	}
}

func OnStop[K comparable, V any](f func()) ProgressTrackerOpt[K, V] {
	return func(pt *ProgressTracker[K, V]) {
		pt.onStop = compose(pt.onStop, f)
	}
}

func WithPeriodicInProgressSnapshot[K comparable, V any](
	ctx context.Context,
	period time.Duration,
	f func([]V),
) ProgressTrackerOpt[K, V] {
	return func(pt *ProgressTracker[K, V]) {
		// TODO: Maybe this should just have one common context /
		// cancel func instead of creating a new one for each
		// invocation.
		ctx, cancel := context.WithCancel(ctx)
		pt.onStop = compose(pt.onStop, cancel)
		pt.inProgressDaemonWg.Add(1)
		go func() {
			defer pt.inProgressDaemonWg.Done()
			ticker := time.NewTicker(period)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					f(pt.InProgressSnapshot())
				}
			}
		}()
	}
}

func NewProgressTracker[K comparable, V any](opts ...ProgressTrackerOpt[K, V]) *ProgressTracker[K, V] {
	tracker := &ProgressTracker[K, V]{
		inProgress: make(map[K]V),
	}
	for _, opt := range opts {
		opt(tracker)
	}
	return tracker
}

func (t *ProgressTracker[K, V]) Add(key K, val V) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addNoLock(key, val)
}

func (t *ProgressTracker[K, V]) Remove(key K) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeNoLock(key)
}

func (t *ProgressTracker[K, V]) Update(key K, f func(*V)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updateNoLock(key, f)
}

func (t *ProgressTracker[K, V]) UpdateOrAdd(key K, f func(*V), defaultVal V) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.updateNoLock(key, f) {
		t.addNoLock(key, defaultVal)
	}
}

func (t *ProgressTracker[K, V]) UpdateAndRemove(key K, f func(*V)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.updateNoLock(key, f) {
		t.removeNoLock(key)
	}
}

func (t *ProgressTracker[K, V]) InProgressSnapshot() []V {
	t.mu.Lock()
	defer t.mu.Unlock()
	vals := make([]V, 0, len(t.inProgress))
	for _, val := range t.inProgress {
		vals = append(vals, val)
	}
	return vals
}

func (t *ProgressTracker[K, V]) Stop() {
	// onStop must be called before wg.Wait for correct synchronization.
	if t.onStop != nil {
		t.onStop()
	}
	t.inProgressDaemonWg.Wait()
}

func (t *ProgressTracker[K, V]) addNoLock(key K, val V) {
	t.inProgress[key] = val
	if t.onAdd != nil {
		t.onAdd(key, val)
	}
}

func (t *ProgressTracker[K, V]) removeNoLock(key K) bool {
	val, ok := t.inProgress[key]
	if !ok {
		return false
	}
	delete(t.inProgress, key)
	if t.onRemove != nil {
		t.onRemove(key, val)
	}
	return true
}

func (t *ProgressTracker[K, V]) updateNoLock(key K, f func(*V)) bool {
	val, ok := t.inProgress[key]
	if !ok {
		return false
	}
	f(&val)
	t.inProgress[key] = val
	return true
}

func compose(f func(), g func()) func() {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	default:
		return func() {
			f()
			g()
		}
	}
}

func composeKV[K, V any](f func(K, V), g func(K, V)) func(K, V) {
	switch {
	case f == nil:
		return g
	case g == nil:
		return f
	default:
		return func(k K, v V) {
			f(k, v)
			g(k, v)
		}
	}
}
