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

var globalRedactor dynamicRedactor

func RedactGlobally(sensitiveValue string) {
	globalRedactor.ConfigureForRedaction(sensitiveValue)
}

func (r *dynamicRedactor) ConfigureForRedaction(sensitiveValue string) {
	r.denyMu.Lock()
	defer r.denyMu.Unlock()

	if _, ok := r.denySet[sensitiveValue]; ok {
		return
	}

	if r.denySet == nil {
		r.denySet = make(map[string]struct{})
	}
	r.denySet[sensitiveValue] = struct{}{}
	r.denySlice = append(r.denySlice, sensitiveValue, "*****")

	r.replacerMu.Lock()
	defer r.replacerMu.Unlock()
	r.replacer = strings.NewReplacer(r.denySlice...)
}

func (r *dynamicRedactor) Redact(s string) string {
	r.replacerMu.RLock()
	defer r.replacerMu.RUnlock()

	return r.replacer.Replace(s)
}
