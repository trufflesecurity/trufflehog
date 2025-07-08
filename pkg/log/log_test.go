package log

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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

func TestWithSentryFailure(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name",
		WithSentry(sentry.ClientOptions{Dsn: "fail"}, nil),
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "error configuring logger")
	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentryFailure(t *testing.T) {
	var buffer bytes.Buffer
	logger, flush := New("service-name", WithConsoleSink(&buffer))
	logger, _, err := AddSentry(logger, sentry.ClientOptions{Dsn: "fail"}, nil)
	assert.NotNil(t, err)
	assert.NotContains(t, err.Error(), "unsupported")

	logger.Info("yay")
	assert.Nil(t, flush())

	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	logger, _ := New("service-name", WithConsoleSink(&buffer))
	logger, flush, err := AddSentry(logger, sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			sentryMessage = event.Message
			return nil
		},
	}, nil)
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
	logger, flush := New("service-name",
		WithConsoleSink(&buffer),
		WithSentry(sentry.ClientOptions{
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				sentryMessage = event.Message
				return nil
			},
		}, nil),
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

func TestGlobalRedaction_Console(t *testing.T) {
	oldState := globalRedactor
	globalRedactor = &dynamicRedactor{
		denySet: make(map[string]struct{}),
	}
	defer func() { globalRedactor = oldState }()

	var buf bytes.Buffer
	logger, flush := New("console-redaction-test",
		WithConsoleSink(&buf, WithGlobalRedaction()),
	)
	RedactGlobally("foo")
	RedactGlobally("bar")

	logger.Info("this foo is :bar",
		"foo", "bar",
		"array", []string{"foo", "bar", "baz"},
		"object", map[string]string{"foo": "bar"})
	require.NoError(t, flush())

	gotParts := strings.Split(buf.String(), "\t")[1:] // The first item is the timestamp
	wantParts := []string{
		"info-0",
		"console-redaction-test",
		"this ***** is :*****",
		"{\"foo\": \"*****\", \"array\": [\"foo\", \"bar\", \"baz\"], \"object\": {\"foo\":\"bar\"}}\n",
	}
	assert.Equal(t, wantParts, gotParts)
}

func TestGlobalRedaction_JSON(t *testing.T) {
	oldState := globalRedactor
	globalRedactor = &dynamicRedactor{
		denySet: make(map[string]struct{}),
	}
	defer func() { globalRedactor = oldState }()

	var jsonBuffer bytes.Buffer
	logger, flush := New("json-redaction-test",
		WithJSONSink(&jsonBuffer, WithGlobalRedaction()),
	)
	RedactGlobally("foo")
	RedactGlobally("bar")
	logger.Info("this foo is :bar",
		"foo", "bar",
		"array", []string{"foo", "bar", "baz"},
		"object", map[string]string{"foo": "bar"})
	require.NoError(t, flush())

	var parsedJSON map[string]any
	require.NoError(t, json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	assert.NotEmpty(t, parsedJSON["ts"])
	delete(parsedJSON, "ts")
	assert.Equal(t,
		map[string]any{
			"level":  "info-0",
			"logger": "json-redaction-test",
			"msg":    "this ***** is :*****",
			"foo":    "*****",
			"array":  []any{"foo", "bar", "baz"},
			"object": map[string]interface{}{"foo": "bar"},
		},
		parsedJSON,
	)
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

func BenchmarkLoggerRedact(b *testing.B) {
	msg := "this is a message with 'foo' in it"
	logKvps := []any{"key", "value", "foo", "bar", "bar", "baz", "longval", "84hblnqwp97ewilbgoab8fhqlngahs6dl3i269haa"}
	redactor := &dynamicRedactor{denySet: make(map[string]struct{})}
	redactor.replacer.CompareAndSwap(nil, strings.NewReplacer())

	b.Run("no redaction", func(b *testing.B) {
		logger, flush := New("redaction-benchmark", WithJSONSink(
			io.Discard,
			func(conf *sinkConfig) { conf.redactor = redactor },
		))
		for i := 0; i < b.N; i++ {
			logger.Info(msg, logKvps...)
		}
		require.NoError(b, flush())
	})
	b.Run("1 redaction", func(b *testing.B) {
		logger, flush := New("redaction-benchmark", WithJSONSink(
			io.Discard,
			func(conf *sinkConfig) { conf.redactor = redactor },
		))
		redactor.configureForRedaction("84hblnqwp97ewilbgoab8fhqlngahs6dl3i269haa")
		for i := 0; i < b.N; i++ {
			logger.Info(msg, logKvps...)
		}
		require.NoError(b, flush())
	})
	b.Run("2 redactions", func(b *testing.B) {
		logger, flush := New("redaction-benchmark", WithJSONSink(
			io.Discard,
			func(conf *sinkConfig) { conf.redactor = redactor },
		))
		redactor.configureForRedaction("84hblnqwp97ewilbgoab8fhqlngahs6dl3i269haa")
		redactor.configureForRedaction("foo")
		for i := 0; i < b.N; i++ {
			logger.Info(msg, logKvps...)
		}
		require.NoError(b, flush())
	})
	b.Run("3 redactions", func(b *testing.B) {
		logger, flush := New("redaction-benchmark", WithJSONSink(
			io.Discard,
			func(conf *sinkConfig) { conf.redactor = redactor },
		))
		redactor.configureForRedaction("84hblnqwp97ewilbgoab8fhqlngahs6dl3i269haa")
		redactor.configureForRedaction("foo")
		redactor.configureForRedaction("bar")
		for i := 0; i < b.N; i++ {
			logger.Info(msg, logKvps...)
		}
		require.NoError(b, flush())
	})
}
