package context

import (
	"context"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
)

var (
	// defaultLogger can be set via SetDefaultLogger.
	// It is initialized to write to stderr. To disable, you can call
	// SetDefaultLogger with logr.Discard().
	defaultLogger logr.Logger
)

func init() {
	defaultLogger, _ = log.New("context", log.WithConsoleSink(os.Stderr))
}

// Context wraps context.Context and includes an additional Logger() method.
type Context interface {
	context.Context
	Logger() logr.Logger
}

// CancelFunc and CancelCauseFunc are type aliases to allow use as if they are
// the same types as the standard library variants.
type CancelFunc = context.CancelFunc
type CancelCauseFunc = context.CancelCauseFunc

// logCtx implements Context.
type logCtx struct {
	// Embed context.Context to get all methods for free.
	context.Context
	log logr.Logger
}

// Logger returns a structured logger.
func (l logCtx) Logger() logr.Logger {
	return l.log
}

// Background returns context.Background with a default logger.
func Background() Context {
	return logCtx{
		log:     defaultLogger,
		Context: context.Background(),
	}
}

// TODO returns context.TODO with a default logger.
func TODO() Context {
	return logCtx{
		log:     defaultLogger,
		Context: context.TODO(),
	}
}

// WithCancel returns context.WithCancel with the log object propagated.
func WithCancel(parent Context) (Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	lCtx := logCtx{
		log:     parent.Logger(),
		Context: ctx,
	}
	return lCtx, cancel
}

// WithCancelCause returns context.WithCancelCause with the log object propagated.
func WithCancelCause(parent Context) (Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	lCtx := logCtx{
		log:     parent.Logger(),
		Context: ctx,
	}
	return lCtx, cancel
}

// WithDeadline returns context.WithDeadline with the log object propagated and
// the deadline added to the structured log values.
func WithDeadline(parent Context, d time.Time) (Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(parent, d)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("deadline", d),
		Context: ctx,
	}
	return lCtx, cancel
}

// WithDeadlineCause returns context.WithDeadlineCause with the log object
// propagated and the deadline added to the structured log values.
func WithDeadlineCause(parent Context, d time.Time, cause error) (Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadlineCause(parent, d, cause)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("deadline", d),
		Context: ctx,
	}
	return lCtx, cancel
}

// WithTimeout returns context.WithTimeout with the log object propagated and
// the timeout added to the structured log values.
func WithTimeout(parent Context, timeout time.Duration) (Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("timeout", timeout),
		Context: ctx,
	}
	return lCtx, cancel
}

// WithTimeoutCause returns context.WithTimeoutCause with the log object
// propagated and the timeout added to the structured log values.
func WithTimeoutCause(parent Context, timeout time.Duration, cause error) (Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeoutCause(parent, timeout, cause)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("timeout", timeout),
		Context: ctx,
	}
	return lCtx, cancel
}

// Cause returns the context.Cause of the context.
func Cause(ctx context.Context) error {
	return context.Cause(ctx)
}

// WithValue returns context.WithValue with the log object propagated and
// the value added to the structured log values (if the key is a string).
func WithValue(parent Context, key, val any) Context {
	logger := parent.Logger()
	if k, ok := key.(string); ok {
		logger = logger.WithValues(k, val)
	}
	return logCtx{
		log:     logger,
		Context: context.WithValue(parent, key, val),
	}
}

// WithValues returns context.WithValue with the log object propagated and
// the values added to the structured log values (if the key is a string).
func WithValues(parent Context, keyAndVals ...any) Context {
	ctx := parent
	for i := 0; i < len(keyAndVals)-1; i += 2 {
		ctx = WithValue(ctx, keyAndVals[i], keyAndVals[i+1])
	}
	return ctx
}

// WithLogger converts a context.Context into a Context by adding a logger.
func WithLogger(parent context.Context, logger logr.Logger) Context {
	return logCtx{
		log:     logger,
		Context: parent,
	}
}

// AddLogger converts a context.Context into a Context. If the underlying type
// is already a Context, that will be returned, otherwise a default logger will
// be added.
func AddLogger(parent context.Context) Context {
	if loggerCtx, ok := parent.(Context); ok {
		return loggerCtx
	}
	return WithLogger(parent, defaultLogger)
}

// SetupDefaultLogger sets the package-level global default logger that will be
// used for Background and TODO contexts. On startup, the default logger will
// be configured to output logs to stderr. Use logr.Discard() to disable all
// logs from Contexts.
func SetDefaultLogger(l logr.Logger) {
	defaultLogger = l
}
