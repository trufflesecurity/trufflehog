package log

import (
	"strings"
	"sync"
)

type dynamicRedactor struct {
	denySet   map[string]struct{}
	denySlice []string
	denyMu    sync.Mutex

	replacer   *strings.Replacer
	replacerMu sync.RWMutex
}

var globalRedactor = dynamicRedactor{
	denySet:  make(map[string]struct{}),
	replacer: strings.NewReplacer(),
}

// RedactGlobally configures the global log redactor to redact the provided value during log emission. The value will be
// redacted in log messages and values that are strings, but not in log keys or values of other types.
func RedactGlobally(sensitiveValue string) {
	globalRedactor.configureForRedaction(sensitiveValue)
}

func (r *dynamicRedactor) configureForRedaction(sensitiveValue string) {
	r.denyMu.Lock()
	defer r.denyMu.Unlock()

	if _, ok := r.denySet[sensitiveValue]; ok {
		return
	}

	r.denySet[sensitiveValue] = struct{}{}
	r.denySlice = append(r.denySlice, sensitiveValue, "*****")

	r.replacerMu.Lock()
	defer r.replacerMu.Unlock()
	r.replacer = strings.NewReplacer(r.denySlice...)
}

func (r *dynamicRedactor) redact(s string) string {
	r.replacerMu.RLock()
	defer r.replacerMu.RUnlock()

	return r.replacer.Replace(s)
}
