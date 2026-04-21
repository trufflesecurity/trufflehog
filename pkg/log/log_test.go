package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// testCore implement zapcore.Core with custom methods.
type testCore struct {
	check   func(zapcore.Entry, *zapcore.CheckedEntry) *zapcore.CheckedEntry
	enabled func(zapcore.Level) bool
	sync    func() error
	with    func([]zapcore.Field) zapcore.Core
	write   func(zapcore.Entry, []zapcore.Field) error
}

func (t *testCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if t.check != nil {
		return t.check(e, ce)
	}
	return ce
}
func (t *testCore) Enabled(l zapcore.Level) bool {
	if t.enabled != nil {
		return t.enabled(l)
	}
	return true
}
func (t *testCore) Sync() error {
	if t.sync != nil {
		return t.sync()
	}
	return nil
}
func (t *testCore) With(fields []zapcore.Field) zapcore.Core {
	if t.with != nil {
		return t.with(fields)
	}
	return t
}
func (t *testCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	if t.write != nil {
		return t.write(ent, fields)
	}
	return nil
}

func TestNew(t *testing.T) {
	var jsonBuffer, consoleBuffer bytes.Buffer
	logger, flush := New("service-name",
		WithJSONSink(&jsonBuffer, WithGlobalRedaction()),
		WithConsoleSink(&consoleBuffer, WithGlobalRedaction()),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	var parsedJSON map[string]any
	assert.Nil(t, json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	assert.NotEmpty(t, parsedJSON["ts"])
	delete(parsedJSON, "ts")
	assert.Equal(t,
		map[string]any{
			"level":  "info-0",
			"logger": "service-name",
			"msg":    "yay",
		},
		parsedJSON,
	)
	assert.Equal(t,
		[]string{"info-0\tservice-name\tyay"},
		splitLines(consoleBuffer.String()),
	)
}

func TestSetLevel(t *testing.T) {
	var buffer bytes.Buffer
	defer SetLevel(0)
	logger, _ := New("service-name", WithConsoleSink(&buffer))

	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, false, logger.GetSink().Enabled(1))
	assert.Equal(t, false, logger.GetSink().Enabled(2))

	SetLevel(1)
	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, true, logger.GetSink().Enabled(1))
	assert.Equal(t, false, logger.GetSink().Enabled(2))

	SetLevel(2)
	assert.Equal(t, true, logger.GetSink().Enabled(0))
	assert.Equal(t, true, logger.GetSink().Enabled(1))
	assert.Equal(t, true, logger.GetSink().Enabled(2))
}

func TestAddSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	client, err := sentry.NewClient(sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			sentryMessage = event.Message
			return nil
		},
	})
	assert.Nil(t, err)
	logger, _ := New("service-name", WithConsoleSink(&buffer))
	logger, flush, err := AddSentry(logger, client, nil)
	assert.Nil(t, err)

	logger.Error(nil, "oops")
	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "oops")
	assert.Contains(t, buffer.String(), "yay")
	assert.Equal(t, "oops", sentryMessage)
}

func TestWithSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	client, err := sentry.NewClient(sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			sentryMessage = event.Message
			return nil
		},
	})
	assert.Nil(t, err)
	logger, flush := New("service-name",
		WithConsoleSink(&buffer),
		WithSentry(client, nil),
	)
	logger.Info("yay")
	logger.Error(nil, "oops")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "yay")
	assert.Contains(t, buffer.String(), "oops")
	assert.Equal(t, "oops", sentryMessage)
}

func TestHumanReadableTimestamp(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name",
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	ts := strings.Split(buffer.String(), "\t")[0]
	assert.NotContains(t, ts, "e+09")

	parsedTime, err := time.Parse(time.RFC3339, ts)
	assert.Nil(t, err)
	assert.Less(t, time.Since(parsedTime), 5*time.Second)
}

func TestAddSink(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger, _ := New("service-name",
		WithConsoleSink(&buf1),
	)
	logger.Info("line 1")
	logger, flush, err := AddSink(logger, WithConsoleSink(&buf2))
	assert.Nil(t, err)
	logger.Info("line 2")
	assert.Nil(t, flush())

	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")
	// buf2 should only have "line 2"
	assert.NotContains(t, buf2.String(), "line 1")
	assert.Contains(t, buf2.String(), "line 2")
}

func TestAddSink_WithKeyValuePairs(t *testing.T) {
	// Arrange: Create a logger with a key-value pair
	var buf1 bytes.Buffer
	logger, cleanup := New("service-name", WithConsoleSink(&buf1))
	t.Cleanup(func() { _ = cleanup })
	logger = logger.WithValues("sink 1 key", "sink 1 value")

	// Arrange: Add a second sink with a new key-value pair
	var buf2 bytes.Buffer
	logger, flush, err := AddSink(logger, WithConsoleSink(&buf2), "sink 2 key", "sink 2 value")
	require.NoError(t, err)

	// Act
	logger.Info("something")
	require.NoError(t, flush())

	// Assert: Confirm that each sink received only its own key-value pair
	assert.Contains(t, buf1.String(), "sink 1")
	assert.NotContains(t, buf1.String(), "sink 2")
	assert.Contains(t, buf2.String(), "sink 2")
	assert.NotContains(t, buf2.String(), "sink 1")
}

func TestStaticLevelSink(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l1 := zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf1, WithLeveler(l1)),
		WithConsoleSink(&buf2, WithLevel(0)),
	)

	logger.Info("line 1")
	SetLevelForControl(l1, 1)
	logger.V(1).Info("line 2")
	assert.Nil(t, flush())

	// buf1 should have both lines
	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")

	// buf2 should only have "line 1"
	assert.Contains(t, buf2.String(), "line 1")
	assert.NotContains(t, buf2.String(), "line 2")
}

func TestWithLeveler(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	l1, l2 := zap.NewAtomicLevel(), zap.NewAtomicLevel()
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf1, WithLeveler(l1)),
		WithConsoleSink(&buf2, WithLeveler(l2)),
	)

	SetLevelForControl(l1, 1)
	SetLevelForControl(l2, 2)

	logger.V(0).Info("line 1")
	logger.V(1).Info("line 2")
	logger.V(2).Info("line 3")
	assert.Nil(t, flush())

	// buf1 should have lines 1 and 2
	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")
	assert.NotContains(t, buf1.String(), "line 3")

	// buf2 should have all lines
	assert.Contains(t, buf2.String(), "line 1")
	assert.Contains(t, buf2.String(), "line 2")
	assert.Contains(t, buf2.String(), "line 3")
}

func splitLines(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	logLines := make([]string, len(lines))
	for i, logLine := range lines {
		// remove timestamp
		logLines[i] = strings.TrimSpace(logLine[strings.Index(logLine, "\t")+1:])
	}
	return logLines
}

func TestToLogger(t *testing.T) {
	var jsonBuffer bytes.Buffer
	l, flush := New("service-name",
		WithJSONSink(&jsonBuffer),
	)
	logger := ToLogger(l)
	logger.Println("yay")
	assert.Nil(t, flush())

	var parsedJSON map[string]any
	assert.Nil(t, json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	assert.NotEmpty(t, parsedJSON["ts"])
	delete(parsedJSON, "ts")
	delete(parsedJSON, "caller") // log.Logger adds a "caller" field
	assert.Equal(t,
		map[string]any{
			"level":  "info-0",
			"logger": "service-name",
			"msg":    "yay",
		},
		parsedJSON,
	)
}

func TestToSlogger(t *testing.T) {
	var jsonBuffer bytes.Buffer
	l, flush := New("service-name", WithJSONSink(&jsonBuffer))
	logger := ToSlogger(l)
	logger.Info("yay")
	assert.Nil(t, flush())

	var parsedJSON map[string]any
	assert.Nil(t, json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	assert.NotEmpty(t, parsedJSON["ts"])
	delete(parsedJSON, "ts")
	delete(parsedJSON, "caller") // slog.Logger adds a "caller" field
	assert.Equal(t,
		map[string]any{
			"level":  "info-0",
			"logger": "service-name",
			"msg":    "yay",
		},
		parsedJSON,
	)
}

func TestSyncFunc(t *testing.T) {
	var syncCalled bool
	core := testCore{
		sync: func() error {
			syncCalled = true
			return nil
		},
	}
	_, flush := New("service-name", &core)
	assert.NoError(t, flush())
	assert.True(t, syncCalled)
}

func TestAddSinkStillSyncs(t *testing.T) {
	var syncCalled [2]bool
	core := testCore{
		sync: func() error {
			syncCalled[0] = true
			return nil
		},
	}
	l, _ := New("service-name", &core)
	_, flush, err := AddSink(l, &testCore{
		sync: func() error {
			syncCalled[1] = true
			return nil
		},
	})
	assert.NoError(t, err)
	assert.NoError(t, flush())
	assert.True(t, syncCalled[0])
	assert.True(t, syncCalled[1])
}
