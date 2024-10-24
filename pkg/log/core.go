package log

import (
	"strings"

	"go.uber.org/zap/zapcore"
)

// redactionCore wraps a zapcore.Core to perform redaction of log messages in
// the message and field values.
type redactionCore struct {
	zapcore.Core
	replacer *strings.Replacer
}

// NewRedactionCore creates a zapcore.Core that performs redaction of logs in
// the message and field values.
func NewRedactionCore(core zapcore.Core, denyList []string) zapcore.Core {
	denyList = stableDedupe(denyList)
	if len(denyList) == 0 {
		return core
	}
	replaceList := make([]string, 0, len(denyList)*2)
	for _, target := range denyList {
		replaceList = append(replaceList, target, "******")
	}
	return &redactionCore{core, strings.NewReplacer(replaceList...)}
}

// Check overrides the embedded zapcore.Core Check() method to add the
// redactionCore to the zapcore.CheckedEntry.
func (c *redactionCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write overrides the embedded zapcore.Core Write() method to redact the
// message and fields before passing them to be written.
func (c *redactionCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Message = c.replacer.Replace(ent.Message)
	for i := range fields {
		fields[i].String = c.replacer.Replace(fields[i].String)
	}
	return c.Core.Write(ent, fields)
}

// stableDedupe is a helper function to deduplicate a slice of elements while
// maintaining their original order.
func stableDedupe(vals []string) []string {
	set := make(map[string]struct{}, len(vals))
	output := make([]string, 0, len(vals))
	for _, val := range vals {
		if val == "" {
			continue
		}
		if _, ok := set[val]; ok {
			continue
		}
		set[val] = struct{}{}
		output = append(output, val)
	}

	return output
}
