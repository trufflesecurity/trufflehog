package log

import "go.uber.org/zap/zapcore"

type suppressCallerCore struct {
	zapcore.Core
}

// Check overrides the embedded zapcore.Core Check() method to add the suppressCallerCore to the zapcore.CheckedEntry.
func (c *suppressCallerCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(ent.Level) {
		return ce
	}

	if wrapped := c.Core.Check(ent, ce); wrapped != nil {
		return wrapped.AddCore(ent, c)
	}

	return ce
}

func (c *suppressCallerCore) With(fields []zapcore.Field) zapcore.Core {
	return &suppressCallerCore{Core: c.Core.With(fields)}
}

func (c *suppressCallerCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Caller = zapcore.EntryCaller{}
	ent.Stack = ""
	return c.Core.Write(ent, fields)
}
