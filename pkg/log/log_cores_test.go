package log

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ignoreEverythingCore is a zap core that rejects all log entries. It is used to test that our custom cores respect
// wrapped core check logic.
type ignoreEverythingCore struct {
	zapcore.Core
}

func (t *ignoreEverythingCore) With(fields []zapcore.Field) zapcore.Core {
	return t.Core.With(fields)
}

func (t *ignoreEverythingCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce
}

var _ zapcore.Core = (*ignoreEverythingCore)(nil)

type TestSuite struct {
	suite.Suite

	oldRedactor *dynamicRedactor
}

func (ts *TestSuite) SetupTest() {
	ts.oldRedactor = globalRedactor
	globalRedactor = &dynamicRedactor{
		denySet: make(map[string]struct{}),
	}
	globalRedactor.replacer.Store(strings.NewReplacer())
}

func (ts *TestSuite) TearDownTest() {
	globalRedactor = ts.oldRedactor
}

func TestCustomCores(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

// This test confirms that when our custom redaction core wraps our custom caller suppression core, redaction occurs.
func (ts *TestSuite) TestCoreComposition_RedactionWrappingCallerSuppression() {
	// Arrange: Create a testable log sink
	var buf bytes.Buffer
	baseCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(&buf)),
		globalLogLevel)

	// Arrange: Create a core stack and set up redaction
	core := NewRedactionCore(&suppressCallerCore{baseCore}, globalRedactor)
	RedactGlobally("sensitive")

	// Arrange: Create a logger
	logger := zapr.NewLogger(zap.New(core))

	// Act
	logger.Info("sensitive message")

	// Assert that redaction executed correctly
	msg := buf.String()
	ts.Assert().Contains(msg, "message")
	ts.Assert().NotContains(msg, "sensitive")
}

// This test confirms that when our custom caller suppression core wraps our custom redaction core, redaction occurs.
func (ts *TestSuite) TestCoreComposition_CallerSuppressionWrappingRedaction() {
	// Arrange: Create a testable log sink
	var buf bytes.Buffer
	baseCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(&buf)),
		globalLogLevel)

	// Arrange: Create a core stack and set up redaction
	core := &suppressCallerCore{NewRedactionCore(baseCore, globalRedactor)}
	RedactGlobally("sensitive")

	// Arrange: Create a logger
	logger := zapr.NewLogger(zap.New(core))

	// Act
	logger.Info("sensitive message")

	// Assert that redaction executed correctly
	msg := buf.String()
	ts.Assert().Contains(msg, "message")
	ts.Assert().NotContains(msg, "sensitive")
}

// This test confirms that the redaction logic executes correctly for console sinks.
func (ts *TestSuite) TestGlobalRedaction_Console() {
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
	ts.Require().NoError(flush())

	gotParts := strings.Split(buf.String(), "\t")[1:] // The first item is the timestamp
	wantParts := []string{
		"info-0",
		"console-redaction-test",
		"this ***** is :*****",
		"{\"foo\": \"*****\", \"array\": [\"foo\", \"bar\", \"baz\"], \"object\": {\"foo\":\"bar\"}}\n",
	}
	ts.Assert().Equal(wantParts, gotParts)
}

// This test confirms that the redaction logic executes correctly for JSON sinks.
func (ts *TestSuite) TestGlobalRedaction_JSON() {
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
	ts.Require().NoError(flush())

	var parsedJSON map[string]any
	ts.Require().NoError(json.Unmarshal(jsonBuffer.Bytes(), &parsedJSON))
	ts.Assert().NotEmpty(parsedJSON["ts"])
	delete(parsedJSON, "ts")
	ts.Assert().Equal(
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

// This test confirms that our custom redaction core respects the "check" logic of any cores it wraps.
func (ts *TestSuite) TestRedactionCore_RespectsWrappedCheckLogic() {
	// Arrange: Create a testable log sink
	var buf bytes.Buffer
	baseCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(&buf)),
		globalLogLevel)

	// Arrange: Set up a core stack
	core := NewRedactionCore(&ignoreEverythingCore{baseCore}, globalRedactor)

	// Arrange: Create a logger
	logger := zapr.NewLogger(zap.New(core))

	// Act
	logger.Info("message")

	// Assert that the wrapped core's check logic was respected
	msg := buf.String()
	ts.Assert().Empty(msg)
}

// This test confirms that our custom caller suppression core respects the "check" logic of any cores it wraps.
func (ts *TestSuite) TestSuppressCallerCore_RespectsWrappedCheckLogic() {
	// Arrange: Create a testable log sink
	var buf bytes.Buffer
	baseCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(&buf)),
		globalLogLevel)

	// Arrange: Set up a core stack
	core := &suppressCallerCore{&ignoreEverythingCore{baseCore}}

	// Arrange: Create a logger
	logger := zapr.NewLogger(zap.New(core))

	// Act
	logger.Info("message")

	// Assert that the wrapped core's check logic was respected
	msg := buf.String()
	ts.Assert().Empty(msg)
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
