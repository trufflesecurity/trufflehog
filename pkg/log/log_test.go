package log

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	var jsonBuffer, consoleBuffer bytes.Buffer
	logger, sync := New("service-name",
		WithJSONSink(&jsonBuffer),
		WithConsoleSink(&consoleBuffer),
	)
	logger.Info("yay")
	sync()

	assert.Contains(t, jsonBuffer.String(), `"logger":"service-name"`)
	assert.Contains(t, jsonBuffer.String(), `"msg":"yay"`)
	assert.Contains(t, consoleBuffer.String(), "info\tservice-name\tyay")
}

func TestSetLevel(t *testing.T) {
	var buffer bytes.Buffer
	logger, _ := New("service-name",
		WithConsoleSink(&buffer),
	)

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
	logger, sync := New("service-name",
		WithSentry(sentry.ClientOptions{Dsn: "fail"}, nil),
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	sync()

	assert.Contains(t, buffer.String(), "error configuring logger")
	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentryFailure(t *testing.T) {
	var buffer bytes.Buffer
	logger, sync := New("service-name",
		WithConsoleSink(&buffer),
	)
	logger, _, err := AddSentry(logger, sentry.ClientOptions{Dsn: "fail"}, nil)
	assert.NotNil(t, err)
	assert.NotContains(t, err.Error(), "unsupported")

	logger.Info("yay")
	sync()

	assert.Contains(t, buffer.String(), "yay")
}

func TestAddSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	logger, sync := New("service-name",
		WithConsoleSink(&buffer),
	)
	logger, sync, err := AddSentry(logger, sentry.ClientOptions{
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			sentryMessage = event.Message
			return nil
		},
	}, nil)
	assert.Nil(t, err)

	logger.Info("yay")
	logger.Error(nil, "oops")
	sync()

	assert.Contains(t, buffer.String(), "yay")
	assert.Contains(t, buffer.String(), "oops")
	assert.Equal(t, "oops", sentryMessage)
}

func TestWithSentry(t *testing.T) {
	var buffer bytes.Buffer
	var sentryMessage string
	logger, sync := New("service-name",
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
	sync()

	assert.Contains(t, buffer.String(), "yay")
	assert.Contains(t, buffer.String(), "oops")
	assert.Equal(t, "oops", sentryMessage)
}

func TestHumanReadableTimestamp(t *testing.T) {
	var buffer bytes.Buffer
	logger, sync := New("service-name",
		WithConsoleSink(&buffer),
	)
	logger.Info("yay")
	sync()

	ts := strings.Split(buffer.String(), "\t")[0]
	assert.NotContains(t, ts, "e+09")

	parsedTime, err := time.Parse(time.RFC3339, ts)
	assert.Nil(t, err)
	assert.Less(t, time.Since(parsedTime), 5*time.Second)
}

func TestAddSink(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger, sync := New("service-name",
		WithConsoleSink(&buf1),
	)
	logger.Info("line 1")
	logger, sync, err := AddSink(logger, WithConsoleSink(&buf2))
	assert.Nil(t, err)
	logger.Info("line 2")
	sync()

	assert.Contains(t, buf1.String(), "line 1")
	assert.Contains(t, buf1.String(), "line 2")
	// buf2 should only have "line 2"
	assert.NotContains(t, buf2.String(), "line 1")
	assert.Contains(t, buf2.String(), "line 2")
}
