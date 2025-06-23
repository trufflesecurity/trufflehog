package feature

import "sync/atomic"

var (
	ForceSkipBinaries  atomic.Bool
	ForceSkipArchives  atomic.Bool
	SkipAdditionalRefs atomic.Bool
	EnableAPKHandler   atomic.Bool
	UserAgentSuffix    AtomicString
)

type AtomicString struct {
	value atomic.Value
}

// Load returns the current value of the atomic string
func (as *AtomicString) Load() string {
	if v := as.value.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Store sets the value of the atomic string
func (as *AtomicString) Store(newValue string) {
	as.value.Store(newValue)
}

// Swap atomically swaps the current string with a new one and returns the old value
func (as *AtomicString) Swap(newValue string) string {
	oldValue := as.Load()
	as.Store(newValue)
	return oldValue
}
