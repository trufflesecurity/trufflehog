package log

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite

	oldRedactor *dynamicRedactor
}

func (ts *TestSuite) SetupTest() {
	ts.oldRedactor = globalRedactor
	globalRedactor = &dynamicRedactor{
		denySet: make(map[string]struct{}),
	}
}

func (ts *TestSuite) TearDownTest() {
	globalRedactor = ts.oldRedactor
}

func TestCustomCores(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

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
