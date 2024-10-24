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

func RedactGlobally(s string) {
	globalRedactor.ConfigureForRedaction(s)
}

func (r *dynamicRedactor) ConfigureForRedaction(s string) {
	r.denyMu.Lock()
	defer r.denyMu.Unlock()

	if _, ok := r.denySet[s]; ok {
		return
	}

	r.denySet[s] = struct{}{}
	r.denySlice = append(r.denySlice, s, "*****")

	r.replacerMu.Lock()
	defer r.replacerMu.Unlock()
	r.replacer = strings.NewReplacer(r.denySlice...)
}

func (r *dynamicRedactor) Redact(s string) string {
	r.replacerMu.RLock()
	defer r.replacerMu.Unlock()

	return r.replacer.Replace(s)
}
