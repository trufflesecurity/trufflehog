// Package logtest has helpers for testing log output.
package logtest

import (
	"fmt"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
)

// DebugContext returns a Context with debug logging turned on, plus the logs written to it.
//
// The logger works like a source's logger when debug is turned on for that source: its sink is set to V(0), and
// context.WithLogLevel raises it to log.DebugLevel. Use it to check that a source writes the debug logs you expect,
// and that it does not write values that must never be logged.
//
//	ctx, logs := logtest.DebugContext()
//	_ = s.Init(ctx, ...)
//	assert.Equal(t, 1, logs.FilterMessage("listing repositories").Len())
func DebugContext() (context.Context, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
	return context.WithLogLevel(ctx, log.DebugLevel), logs
}

// SourceFields are the fields the source manager adds to every source's context. Every line a source logs through
// its context carries them.
var SourceFields = []string{"job_id", "source_id", "source_name", "source_type"}

// SourceContext returns a Context with the source fields set, the way the source manager sets them, plus the logs
// written to it. With debug true, debug logging is turned on, like DebugContext. With debug false, the context
// writes only V(0) and above, like a normal run.
//
// Source tests use it with the Check functions below, which check what must hold for every source, never the text
// or the number of lines:
//
//	ctx, logs := logtest.SourceContext(true)
//	require.NoError(t, s.Init(ctx, ...))
//	logtest.CheckInitLine(t, logs.All())
//	// scan
//	logtest.CheckSourceLines(t, logs.All(), testSecret)
func SourceContext(debug bool) (context.Context, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
	if debug {
		ctx = context.WithLogLevel(ctx, log.DebugLevel)
	}
	return context.WithValues(ctx,
		"job_id", 1,
		"source_id", 1,
		"source_name", "test source",
		"source_type", "test",
	), logs
}

// CheckInitLine fails the test if entries has no V(1) line. Pass it the lines logged by Init only, so the line is
// known to come from Init.
func CheckInitLine(t testing.TB, entries []observer.LoggedEntry) {
	t.Helper()
	for _, entry := range entries {
		if entry.Level == zapcore.Level(-1) {
			return
		}
	}
	t.Errorf("Init logged no V(1) line, got %d lines", len(entries))
}

// CheckSourceLines fails the test if a line is missing one of the SourceFields, or if its message or fields contain
// one of secrets. A missing field means the line was not logged through the context the source was given. It also
// fails with no lines at all, since then nothing was checked.
func CheckSourceLines(t testing.TB, entries []observer.LoggedEntry, secrets ...string) {
	t.Helper()
	if len(entries) == 0 {
		t.Errorf("no lines were logged, so there is nothing to check")
		return
	}
	for _, entry := range entries {
		fields := entry.ContextMap()
		for _, key := range SourceFields {
			assert.Contains(t, fields, key, "line %q", entry.Message)
		}
		for _, secret := range secrets {
			assert.NotContains(t, entry.Message, secret, "line %q", entry.Message)
			assert.NotContains(t, fmt.Sprint(fields), secret, "line %q", entry.Message)
		}
	}
}

// CheckNoDebugLines fails the test if any line is more verbose than V(0). Use it on a run with debug off.
func CheckNoDebugLines(t testing.TB, entries []observer.LoggedEntry) {
	t.Helper()
	for _, entry := range entries {
		assert.GreaterOrEqual(t, entry.Level, zapcore.InfoLevel, "debug line %q with debug off", entry.Message)
	}
}
