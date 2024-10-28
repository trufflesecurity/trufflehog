package log

import (
	"strings"
	"sync"
	"sync/atomic"
)

type dynamicRedactor struct {
	denySet   map[string]struct{}
	denySlice []string
	denyMu    sync.Mutex

	replacer atomic.Pointer[strings.Replacer]
}

var globalRedactor *dynamicRedactor

func init() {
	globalRedactor = &dynamicRedactor{denySet: make(map[string]struct{})}
	globalRedactor.replacer.CompareAndSwap(nil, strings.NewReplacer())
}

// RedactGlobally configures the global log redactor to redact the provided value during log emission. The value will be
// redacted in log messages and values that are strings, but not in log keys or values of other types.
func RedactGlobally(sensitiveValue string) {
	globalRedactor.configureForRedaction(sensitiveValue)
}

func (r *dynamicRedactor) configureForRedaction(sensitiveValue string) {
	if sensitiveValue == "" {
		return
	}

	r.denyMu.Lock()
	defer r.denyMu.Unlock()

	if _, ok := r.denySet[sensitiveValue]; ok {
		return
	}

	r.denySet[sensitiveValue] = struct{}{}
	r.denySlice = append(r.denySlice, sensitiveValue, "*****")

	r.replacer.Store(strings.NewReplacer(r.denySlice...))
}

func (r *dynamicRedactor) redact(s string) string {
	return r.replacer.Load().Replace(s)
}
