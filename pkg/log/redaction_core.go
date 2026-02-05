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

// Check overrides the embedded zapcore.Core Check() method to add the
// redactionCore to the zapcore.CheckedEntry.
func (c *redactionCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(ent.Level) {
		return ce
	}

	if wrapped := c.Core.Check(ent, ce); wrapped != nil {
		return wrapped.AddCore(ent, c)
	}

	return ce
}

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
