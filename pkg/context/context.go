package context

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/go-logr/logr"
)

var (
	// defaultLogger can be set via SetDefaultLogger.
	defaultLogger logr.Logger = logr.Discard()
)

// Context wraps context.Context and includes an additional Logger() method.
type Context interface {
	context.Context
	Logger() logr.Logger
	Parent() context.Context
	SetParent(ctx context.Context) Context
}

// Parent returns the parent context.
func (l logCtx) Parent() context.Context {
	return l.Context
}

// SetParent sets the parent context on the context.
func (l logCtx) SetParent(ctx context.Context) Context {
	l.Context = ctx
	return l
}

type CancelFunc context.CancelFunc

// logCtx implements Context.
type logCtx struct {
	// Embed context.Context to get all methods for free.
	context.Context
	log logr.Logger
	err *error
}

// Logger returns a structured logger.
func (l logCtx) Logger() logr.Logger {
	return l.log
}

func (l logCtx) Err() error {
	if l.err != nil && *l.err != nil {
		return *l.err
	}
	return l.Context.Err()
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
	return captureCancelCallstack(lCtx, cancel)
}

// WithDeadline returns context.WithDeadline with the log object propagated and
// the deadline added to the structured log values.
func WithDeadline(parent Context, d time.Time) (Context, context.CancelFunc) {
	ctx, cancel := context.WithDeadline(parent, d)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("deadline", d),
		Context: ctx,
	}
	return captureCancelCallstack(lCtx, cancel)
}

// WithTimeout returns context.WithTimeout with the log object propagated and
// the timeout added to the structured log values.
func WithTimeout(parent Context, timeout time.Duration) (Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	lCtx := logCtx{
		log:     parent.Logger().WithValues("timeout", timeout),
		Context: ctx,
	}
	return captureCancelCallstack(lCtx, cancel)
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
// used for Background and TODO contexts.
func SetDefaultLogger(l logr.Logger) {
	defaultLogger = l
}

// captureCancelCallstack is a helper function to capture the callstack where
// the cancel function was first called.
func captureCancelCallstack(ctx logCtx, f context.CancelFunc) (Context, context.CancelFunc) {
	if ctx.err == nil {
		var err error
		ctx.err = &err
	}
	return ctx, func() {
		// We must check Err() before calling f() since f() sets the error.
		// If there's already an error, do nothing special.
		if ctx.Err() != nil {
			f()
			return
		}
		f()
		// Set the error with the stacktrace if the err pointer is non-nil.
		*ctx.err = fmt.Errorf(
			"%w (canceled at %v\n%s)",
			ctx.Err(), time.Now(), string(debug.Stack()),
		)
	}
}
