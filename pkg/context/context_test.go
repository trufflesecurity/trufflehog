package context

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

// testLogger is a helper function to create a logger with a closure callback.
func testLogger(t *testing.T, f func(zapcore.Entry)) logr.Logger {
	return zapr.NewLogger(zaptest.NewLogger(t,
		zaptest.WrapOptions(zap.Hooks(func(e zapcore.Entry) error {
			f(e)
			return nil
		}))))
}

// infoCounterContext is a helper function to create a Context that will count
// the number of Info messages logged.
func infoCounterContext(t *testing.T) (Context, *int) {
	var infoCount int
	logger := testLogger(t, func(e zapcore.Entry) {
		if e.Level == zap.InfoLevel {
			infoCount++
		}
	})
	return WithLogger(context.Background(), logger), &infoCount
}

func TestWithCancel(t *testing.T) {
	parentCtx, infoCount := infoCounterContext(t)
	ctx, cancel := WithCancel(parentCtx)
	cancel()
	assert.Equal(t, 0, *infoCount)
	select {
	case <-ctx.Done():
		ctx.Logger().Info("yay")
	case <-time.After(1 * time.Second):
		assert.Fail(t, "context should be done")
	}
	assert.Equal(t, 1, *infoCount)
}

func TestWithTimeout(t *testing.T) {
	parentCtx, infoCount := infoCounterContext(t)
	ctx, cancel := WithTimeout(parentCtx, 10*time.Millisecond)
	defer cancel()

	assert.Equal(t, 0, *infoCount)
	select {
	case <-ctx.Done():
		ctx.Logger().Info("yay")
	case <-time.After(1 * time.Second):
		assert.Fail(t, "context should be done")
	}
	assert.Equal(t, 1, *infoCount)

	ctx, cancel = WithTimeout(parentCtx, 1*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		assert.Fail(t, "context should not be done")
	case <-time.After(10 * time.Millisecond):
		ctx.Logger().Info("yay")
	}
	assert.Equal(t, 2, *infoCount)
}

func TestWithLogger(t *testing.T) {
	var infoCount int
	logger := testLogger(t, func(e zapcore.Entry) {
		if e.Level == zap.InfoLevel {
			infoCount++
		}
	})

	ctx := WithLogger(context.Background(), logger)
	assert.Equal(t, logger, ctx.Logger())

	assert.Equal(t, 0, infoCount)
	ctx.Logger().Info("yay")
	assert.Equal(t, 1, infoCount)
}

func TestAsContext(t *testing.T) {
	var gotValue any
	normalFuncThatTakesContext := func(ctx context.Context) {
		if logCtx, ok := ctx.(Context); ok {
			logCtx.Logger().Info("yay")
		}
		gotValue = ctx.Value("key")
	}
	parentCtx, infoCount := infoCounterContext(t)
	ctx := WithValue(parentCtx, "key", "value")

	assert.Equal(t, 0, *infoCount)
	normalFuncThatTakesContext(ctx)
	assert.Equal(t, 1, *infoCount)
	assert.Equal(t, "value", gotValue)
}

func TestWithValues(t *testing.T) {
	var buffer bytes.Buffer
	logger, sync := log.New("test",
		log.WithConsoleSink(&buffer),
	)
	defer func(prevLogger logr.Logger) {
		defaultLogger = prevLogger
	}(defaultLogger)
	SetDefaultLogger(logger)

	{
		ctx1 := Background()
		ctx1.Logger().Info("only a", "a", 0)

		ctx2 := WithValue(ctx1, "b", 1)
		ctx2.Logger().Info("only b")
		assert.Equal(t, 1, ctx2.Value("b"))

		ctx3 := WithLogger(ctx2, ctx2.Logger().WithValues("c", 2, "d", 3))
		ctx3.Logger().Info("bcd")

		ctx2.Logger().Info("only b again")

		type customKey string
		ctx4 := WithValue(Background(), customKey("foo"), "bar")
		// foo:bar shouldn't be added to the logger because the key isn't a string
		ctx4.Logger().Info("foo")

		ctx5 := WithValues(ctx2, "e", 4, "f", 5, 6, "six")
		ctx5.Logger().Info("bef")
		assert.Equal(t, "six", ctx5.Value(6))

		ctx6 := WithValues(ctx2, "what does this do?")
		ctx6.Logger().Info("silently fail I suppose")
	}
	assert.Nil(t, sync())
	logs := strings.Split(strings.TrimSpace(buffer.String()), "\n")

	assert.Equal(t, 7, len(logs))
	assert.Contains(t, logs[0], `{"a": 0}`)
	assert.Contains(t, logs[1], `{"b": 1}`)
	assert.Contains(t, logs[2], `{"b": 1, "c": 2, "d": 3}`)
	assert.Contains(t, logs[3], `{"b": 1}`)
	assert.NotContains(t, logs[4], `{"foo": "bar"}`)
	assert.Contains(t, logs[5], `{"b": 1, "e": 4, "f": 5}`)
	assert.Contains(t, logs[6], `silently fail`)
	assert.NotContains(t, logs[6], `what does this do?`)
}

func TestDefaultLogger(t *testing.T) {
	var panicked bool
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
		assert.False(t, panicked)
	}()
	ctx := Background()
	ctx.Logger().Info("this shouldn't panic")
}

func TestRace(t *testing.T) {
	ctx, cancel := WithCancel(Background())
	go cancel()
	go func() { _ = ctx.Err() }()
	cancel()
	_ = ctx.Err()
}

func TestCause(t *testing.T) {
	ctx, cancel := WithCancelCause(Background())
	err := fmt.Errorf("oh no")
	cancel(err)
	assert.Equal(t, err, Cause(ctx))
}
