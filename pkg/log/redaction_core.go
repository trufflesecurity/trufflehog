package log

import (
	"go.uber.org/zap/zapcore"
)

// redactionCore wraps a zapcore.Core to perform redaction of log messages in
// the message and field values.
type redactionCore struct {
	zapcore.Core
	redactor *dynamicRedactor
}

// NewRedactionCore creates a zapcore.Core that performs redaction of logs in
// the message and field values.
func NewRedactionCore(core zapcore.Core, redactor *dynamicRedactor) zapcore.Core {
	return &redactionCore{core, redactor}
}

// Check determines whether the supplied Entry should be logged and, if it should, adds the core to the entry.
func (c *redactionCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(ent.Level) {
		return ce
	}

	// Check to see whether the wrapped core would write, and if so, add this core to the CheckedEntry. We do not pass
	// the CheckedEntry directly to the wrapped core, because if we do, the wrapped core will probably add itself as a
	// side effect, which would result in the wrapped core executing its own writes, which would be both duplicative and
	// unredacted.
	if wrapped := c.Core.Check(ent, nil); wrapped != nil {
		return ce.AddCore(ent, c)
	}

	return ce
}

// With adds structured context to the Core. It does not do anything interesting and is only implemented at all because
// of the way zap works.
func (c *redactionCore) With(fields []zapcore.Field) zapcore.Core {
	return NewRedactionCore(c.Core.With(fields), c.redactor)
}

// Write overrides the embedded zapcore.Core Write() method to redact the message and fields before passing them to be
// written. Only message and string values are redacted; keys and non-string values (e.g. those inside of arrays and
// structured objects) are not redacted.
func (c *redactionCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Message = c.redactor.redact(ent.Message)
	for i := range fields {
		fields[i].String = c.redactor.redact(fields[i].String)
	}
	return c.Core.Write(ent, fields)
}
