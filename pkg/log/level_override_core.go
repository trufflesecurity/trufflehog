package log

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// levelOverrideCore wraps a zapcore.Core so that one logger can write more verbose logs than the rest of the program.
//
// The rule is: if the override allows a V(1) to V(5) log, that log goes to every sink that is currently writing V(0)
// logs. A sink that is turned off (for example with --log-level=-1) does not take V(0) logs, so it stays quiet. V(0),
// warning, and error logs are not touched at all.
type levelOverrideCore struct {
	zapcore.Core
	enabler zapcore.LevelEnabler
}

// WithLevelOverride returns a logger that also writes logs allowed by enabler, even when the normal log level would
// drop them. Loggers made from the returned logger (with WithValues, WithName, and so on) keep the override. The
// override can only add logs; it never hides logs the normal level would write.
//
// Loggers that are not backed by zap (for example logr.Discard()) are returned unchanged.
func WithLevelOverride(l logr.Logger, enabler zapcore.LevelEnabler) logr.Logger {
	zapLogger, err := getZapLogger(l)
	if err != nil {
		return l
	}

	zapLogger = zapLogger.WithOptions(
		zap.WrapCore(func(core zapcore.Core) zapcore.Core {
			return &levelOverrideCore{Core: core, enabler: enabler}
		}),
		// zapr.NewLogger adds two frames of caller skip on top of the ones the existing logger already has. Take them
		// back off so the caller is still reported correctly. AddSink does the same thing for the same reason.
		zap.AddCallerSkip(-2),
	)
	// Building a new logr.Logger resets its V level, so carry it over.
	return zapr.NewLogger(zapLogger).V(l.GetV())
}

// Enabled reports whether a log at this level could be written. zap and logr call this before doing any work, so it
// has to say yes for debug logs the override allows, but only if some sink takes V(0) logs.
//
// Sentry counts as such a sink, because it keeps V(0) logs as breadcrumbs. So with logging turned off but Sentry
// attached, this still says yes: debug logs get built and passed to Sentry, which then drops them. Nothing is
// written; it only costs some work, the same as V(0) logs already do in that setup.
func (c *levelOverrideCore) Enabled(level zapcore.Level) bool {
	if c.Core.Enabled(level) {
		return true
	}
	return c.overrides(level) && c.Core.Enabled(zapcore.InfoLevel)
}

// Check decides which sinks should write the log.
func (c *levelOverrideCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	// If the override has nothing to say about this log, use the normal level rules.
	if !c.overrides(ent.Level) {
		return c.Core.Check(ent, ce)
	}

	// Ask the wrapped core which sinks would write this log if it were a V(0) log. Those sinks add themselves to the
	// CheckedEntry, so they do the writing, and any redaction or caller suppression they have still runs. Then put
	// the real level back so the log is not reported as V(0).
	//
	// Sentry joins here too, because it takes V(0) logs as breadcrumbs. It checks the level again in its own Write
	// and drops debug logs, so they never become breadcrumbs or events. That relies on zapsentry, not on this code;
	// TestWithLevelOverride_SentryGetsNoDebugLines will catch it if that ever changes.
	asInfo := ent
	asInfo.Level = zapcore.InfoLevel
	ce = c.Core.Check(asInfo, ce)
	if ce != nil {
		ce.Level = ent.Level
	}
	return ce
}

// With adds structured context to the Core and keeps the override on the new Core.
func (c *levelOverrideCore) With(fields []zapcore.Field) zapcore.Core {
	return &levelOverrideCore{Core: c.Core.With(fields), enabler: c.enabler}
}

// overrides reports whether the override should decide where a log at this level goes. That is only true for logs
// more verbose than V(0) that the override allows.
func (c *levelOverrideCore) overrides(level zapcore.Level) bool {
	return level < zapcore.InfoLevel && c.enabler.Enabled(level)
}
