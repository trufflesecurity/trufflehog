package hasher

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// MutexHasher wraps a Hasher with a sync.Mutex to ensure thread-safe access.
// This implementation is safe for concurrent use.
type MutexHasher struct {
	hasher Hasher
	mu     sync.Mutex
}

// NewMutexHasher creates a new MutexHasher wrapping the provided Hasher.
func NewMutexHasher(hasher Hasher) *MutexHasher {
	return &MutexHasher{hasher: hasher}
}

// HashWithContext synchronizes access to the underlying Hasher using a mutex and respects context cancellation.
func (m *MutexHasher) HashWithContext(ctx context.Context, data []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.hasher.HashWithContext(ctx, data)
	}
}

// Hash synchronizes access to the underlying Hasher using a mutex.
func (m *MutexHasher) Hash(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hasher.Hash(data)
}
