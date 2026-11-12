package log

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// debugOverride is the override used by most tests: it allows everything up to V(5).
var debugOverride = zapcore.Level(-DebugLevel)

func TestWithLevelOverride_OnlyOverrideLoggerWritesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(0)))
	debugLogger := WithLevelOverride(logger, debugOverride)

	logger.V(5).Info("normal debug line")
	debugLogger.V(5).Info("override debug line")
	debugLogger.Info("override info line")
	require.NoError(t, flush())

	assert.NotContains(t, buf.String(), "normal debug line")
	assert.Contains(t, buf.String(), "override debug line")
	assert.Contains(t, buf.String(), "override info line")
	// The debug line keeps its real level and is not reported as V(0).
	assert.Contains(t, buf.String(), "info-5\tservice-name\toverride debug line")

	assert.False(t, logger.V(5).Enabled())
	assert.True(t, debugLogger.V(5).Enabled())
}

func TestWithLevelOverride_RespectsOverrideLevel(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(0)))
	logger = WithLevelOverride(logger, zapcore.Level(-2))

	logger.V(2).Info("line 2")
	logger.V(3).Info("line 3")
	require.NoError(t, flush())

	assert.Contains(t, buf.String(), "line 2")
	assert.NotContains(t, buf.String(), "line 3")
}

func TestWithLevelOverride_DerivedLoggersKeepOverride(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(0)))
	logger = WithLevelOverride(logger, debugOverride)

	logger.WithValues("key", "value").WithName("child").V(5).Info("derived debug line")
	require.NoError(t, flush())

	assert.Contains(t, buf.String(), "service-name.child\tderived debug line")
	assert.Contains(t, buf.String(), `{"key": "value"}`)
}

func TestWithLevelOverride_KeepsVLevel(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(0)))
	logger = WithLevelOverride(logger.V(2), debugOverride)

	logger.Info("line at V(2)")
	require.NoError(t, flush())

	assert.Contains(t, buf.String(), "info-2\tservice-name\tline at V(2)")
}

func TestWithLevelOverride_Nested(t *testing.T) {
	// Adding a second override on top of the first one works, and the more verbose one wins.
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(0)))
	logger = WithLevelOverride(WithLevelOverride(logger, zapcore.Level(-2)), debugOverride)

	logger.V(5).Info("debug line")
	require.NoError(t, flush())

	assert.Equal(t, 1, strings.Count(buf.String(), "debug line"))
}

func TestWithLevelOverride_NeverLowersLevel(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buf, WithLevel(5)))
	logger = WithLevelOverride(logger, zapcore.Level(-2))

	logger.V(5).Info("debug line")
	require.NoError(t, flush())

	assert.Contains(t, buf.String(), "debug line")
}

func TestWithLevelOverride_LoggingOff(t *testing.T) {
	// --log-level=-1 sets the level to "fatal", which turns off normal logs. Sentry is added too, because it still
	// takes info logs as breadcrumbs, and that must not turn the console sink back on.
	client, err := sentry.NewClient(sentry.ClientOptions{})
	require.NoError(t, err)

	var buf bytes.Buffer
	level := zap.NewAtomicLevel()
	SetLevelForControl(level, -5)
	logger, flush := New("service-name",
		WithConsoleSink(&buf, WithLeveler(level)),
		WithSentry(client, nil),
	)
	logger = WithLevelOverride(logger, debugOverride)

	logger.V(5).Info("debug line")
	logger.Info("info line")
	require.NoError(t, flush())

	assert.Empty(t, buf.String())
}

func TestWithLevelOverride_RedactionAndSuppressCaller(t *testing.T) {
	// Use a fresh global redactor so this test does not leak redactions into other tests.
	oldRedactor := globalRedactor
	t.Cleanup(func() { globalRedactor = oldRedactor })
	globalRedactor = &dynamicRedactor{denySet: make(map[string]struct{})}
	globalRedactor.replacer.Store(strings.NewReplacer())
	RedactGlobally("hunter2")

	// This is the same sink setup the on-prem thog scanner uses.
	var buf bytes.Buffer
	logger, flush := NewWithCaller("service-name", true,
		WithConsoleSink(&buf, WithLevel(0), WithGlobalRedaction(), WithSuppressCaller()),
	)
	logger = WithLevelOverride(logger, debugOverride)

	logger.V(5).Info("password is hunter2", "password", "hunter2")
	require.NoError(t, flush())

	assert.Contains(t, buf.String(), "password is *****")
	assert.NotContains(t, buf.String(), "hunter2")
	assert.NotContains(t, buf.String(), "level_override_core_test.go")
}

func TestWithLevelOverride_SentryGetsNoDebugLines(t *testing.T) {
	var events []*sentry.Event
	client, err := sentry.NewClient(sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			events = append(events, event)
			return nil
		},
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	logger, flush := New("service-name",
		WithConsoleSink(&buf, WithLevel(0)),
		WithSentry(client, nil),
	)
	logger = WithLevelOverride(logger, debugOverride)

	logger.Info("info line")
	logger.V(5).Info("debug line")
	logger.Error(nil, "oops")
	require.NoError(t, flush())

	// The console sink gets the debug line.
	assert.Contains(t, buf.String(), "debug line")

	// Sentry gets one event, with the info line as a breadcrumb but not the debug line.
	require.Len(t, events, 1)
	assert.Equal(t, "oops", events[0].Message)
	var breadcrumbs []string
	for _, b := range events[0].Breadcrumbs {
		breadcrumbs = append(breadcrumbs, b.Message)
	}
	assert.Contains(t, breadcrumbs, "info line")
	assert.NotContains(t, breadcrumbs, "debug line")
}

func TestWithLevelOverride_CallerAndWrittenOnce(t *testing.T) {
	var buf bytes.Buffer
	logger, flush := NewWithCaller("service-name", true, WithConsoleSink(&buf, WithLevel(0)))
	logger = WithLevelOverride(logger, debugOverride)

	_, _, line, _ := runtime.Caller(0)
	logger.V(5).Info("debug line")
	require.NoError(t, flush())

	lines := splitLines(buf.String())
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], fmt.Sprintf("log/level_override_core_test.go:%d", line+1))
}

func TestWithLevelOverride_AddSinkAfterOverride(t *testing.T) {
	// A sink added after the override is not covered by it, but logging still works.
	var buf1, buf2 bytes.Buffer
	logger, _ := New("service-name", WithConsoleSink(&buf1, WithLevel(0)))
	logger = WithLevelOverride(logger, debugOverride)
	logger, flush, err := AddSink(logger, WithConsoleSink(&buf2, WithLevel(0)))
	require.NoError(t, err)

	logger.V(5).Info("debug line")
	require.NoError(t, flush())

	assert.Equal(t, 1, strings.Count(buf1.String(), "debug line"))
	assert.Empty(t, buf2.String())
}

func TestWithLevelOverride_NonZapLogger(t *testing.T) {
	logger := logr.Discard()
	assert.Equal(t, logger, WithLevelOverride(logger, debugOverride))
}
