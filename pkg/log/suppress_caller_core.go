package log

import "go.uber.org/zap/zapcore"

// suppressCallerCore is a zap core that removes caller information from zap entries before writing. It is intended to
// be used as a wrapper around particular zap cores that you do not want to write caller information to.
//
// If you want to exclude caller information from the entire logger, don't use this core - instead, do not enable caller
// information at the logger level. (That will be much faster than using this core, because zap will refrain from
// generating caller information in the first place, rather than generating it and then throwing it away.)
type suppressCallerCore struct {
	zapcore.Core
}

// Check determines whether the supplied Entry should be logged and, if it should, adds the core to the entry. It does
// not do anything interesting and is only implemented at all because of the way zap works.
func (c *suppressCallerCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(ent.Level) {
		return ce
	}

	// Check to see whether the wrapped core would write, and if so, add this core to the CheckedEntry. We do not pass
	// the CheckedEntry directly to the wrapped core, because if we do, the wrapped core will probably add itself as a
	// side effect, which would result in the wrapped core executing its own writes, which would be both duplicative and
	// without caller suppression.
	if wrapped := c.Core.Check(ent, nil); wrapped != nil {
		// If we add the wrapped core, then that core will generate its own writes - which won't have caller information
		// suppressed! Instead, we only add this core, which will delegate its (caller-suppressed) writes to the wrapped
		// core.
		return ce.AddCore(ent, c)
	}

	return ce
}

// With adds structured context to the Core. It does not do anything interesting and is only implemented at all because
// of the way zap works.
func (c *suppressCallerCore) With(fields []zapcore.Field) zapcore.Core {
	return &suppressCallerCore{Core: c.Core.With(fields)}
}

// Write removes caller information from a zap entry and then passes it to the wrapped core for writing.
func (c *suppressCallerCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	ent.Caller = zapcore.EntryCaller{}
	ent.Stack = ""
	return c.Core.Write(ent, fields)
}
