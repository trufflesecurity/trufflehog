package log

import (
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"time"

	"github.com/TheZeroSlave/zapsentry"
	"github.com/getsentry/sentry-go"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type SyncFunc func() error

type SinkOption func(*sinkConfig)

// New creates a new log object with the provided configurations. If no sinks
// are provided, a no-op sink will be used. Returns the logger and a cleanup
// function that should be executed before the program exits.
func New(service string, cores ...zapcore.Core) (logr.Logger, SyncFunc) {
	return NewWithCaller(service, false, cores...)
}

// NewWithCaller creates a new logger named after the specified service with the provided sink configurations. If
// addCaller is true, call site information will be attached to each emitted log message. (This behavior can be disabled
// on a per-sink basis using WithSuppressCaller.)
func NewWithCaller(service string, addCaller bool, cores ...zapcore.Core) (logr.Logger, SyncFunc) {
	// create logger
	zapLogger := zap.New(zapcore.NewTee(cores...), zap.WithCaller(addCaller))
	logger := zapr.NewLogger(zapLogger).WithName(service)

	return logger, zapLogger.Sync
}

// WithSentry adds sentry integration to the logger.
func WithSentry(client *sentry.Client, tags map[string]string) zapcore.Core {
	// create sentry core
	cfg := zapsentry.Configuration{
		Tags:              tags,
		Level:             zapcore.ErrorLevel,
		EnableBreadcrumbs: true,
		BreadcrumbLevel:   zapcore.InfoLevel,
	}
	core, err := zapsentry.NewCore(cfg, zapsentry.NewSentryClientFromClient(client))
	if err != nil {
		// NewCore should never fail because NewSentryClientFromClient
		// never returns an error and NewCore only returns an error if
		// the zapsentry.Configuration is invalid, which would indicate
		// a programmer error.
		panic(err)
	}

	return core
}

type sinkConfig struct {
	encoder        zapcore.Encoder
	sink           zapcore.WriteSyncer
	level          levelSetter
	redactor       *dynamicRedactor
	suppressCaller bool
}

// WithJSONSink adds a JSON encoded output to the logger.
func WithJSONSink(sink io.Writer, opts ...SinkOption) zapcore.Core {
	return newCore(
		zapcore.NewJSONEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(sink)),
		globalLogLevel,
		opts...,
	)
}

// WithConsoleSink adds a console-style output to the logger.
func WithConsoleSink(sink io.Writer, opts ...SinkOption) zapcore.Core {
	return newCore(
		zapcore.NewConsoleEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(sink)),
		globalLogLevel,
		opts...,
	)
}

func defaultEncoderConfig() zapcore.EncoderConfig {
	conf := zap.NewProductionEncoderConfig()
	// Use more human-readable time format.
	conf.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	conf.EncodeLevel = func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		if level == zapcore.ErrorLevel {
			enc.AppendString("error")
			return
		}
		enc.AppendString(fmt.Sprintf("info-%d", -int8(level)))
	}
	return conf
}

// WithCore adds any user supplied zap core to the logger.
func WithCore(core zapcore.Core) zapcore.Core {
	return core
}

// AddSentry initializes a sentry client and extends an existing
// logr.Logger with the hook.
func AddSentry(l logr.Logger, client *sentry.Client, tags map[string]string) (logr.Logger, SyncFunc, error) {
	return AddSink(l, WithSentry(client, tags))
}

// AddSink extends an existing logr.Logger with a new sink. It returns the new logr.Logger, a cleanup function, and an
// error.
//
// The new sink will not inherit any of the existing logger's key-value pairs. Key-value pairs can be added to the new
// sink specifically by passing them to this function.
func AddSink(l logr.Logger, core zapcore.Core, keysAndValues ...any) (logr.Logger, SyncFunc, error) {
	// New key-value pairs cannot be ergonomically added directly to cores. logr has code to do it, but that code is not
	// exported. Rather than replicating it ourselves, we indirectly use it by creating a temporary logger for the new
	// core, adding the key-value pairs to the temporary logger, and then extracting the temporary logger's modified
	// core.
	newSinkLogger := zapr.NewLogger(zap.New(core))
	newSinkLogger = newSinkLogger.WithValues(keysAndValues...)
	newCoreLogger, err := getZapLogger(newSinkLogger)
	if err != nil {
		return l, nil, fmt.Errorf("error setting up new key-value pairs: %w", err)
	}
	newSinkCore := newCoreLogger.Core()

	zapLogger, err := getZapLogger(l)
	if err != nil {
		return l, nil, errors.New("unsupported logr implementation")
	}

	newLoggerOptions := []zap.Option{
		// Tee the new core together with the original core
		zap.WrapCore(func(core zapcore.Core) zapcore.Core { return zapcore.NewTee(core, newSinkCore) }),

		// CMR: zapr.NewLogger, for whatever reason, assumes that the passed-in logger doesn't have its caller frame
		// adjustment already set up, so it adds a frame skip of 2. However, that assumption doesn't hold here because
		// we're adding a core to an existing logger rather than creating a new one. I can't figure out a way to disable
		// this automatic frame adjustment, so we compensate for it with the hamfisted kludge of a compensating offset.
		zap.AddCallerSkip(-2),
	}

	zapLogger = zapLogger.WithOptions(newLoggerOptions...)
	newLogger := zapr.NewLogger(zapLogger)
	return newLogger, zapLogger.Sync, nil
}

// getZapLogger is a helper function that gets the underlying zap logger from a
// logr.Logger interface.
func getZapLogger(l logr.Logger) (*zap.Logger, error) {
	if u, ok := l.GetSink().(zapr.Underlier); ok {
		return u.GetUnderlying(), nil
	}
	return nil, errors.New("not a zapr logger")
}

// WithLevel sets the sink's level to a static level. This option prevents
// changing the log level for this sink later on.
func WithLevel(level int8) SinkOption {
	return WithLeveler(
		// Zap's levels get more verbose as the number gets smaller, as explained
		// by zapr here: https://github.com/go-logr/zapr#increasing-verbosity
		// For example setting the level to -2 below, means log.V(2) will be enabled.
		zap.NewAtomicLevelAt(zapcore.Level(-level)),
	)
}

// WithLeveler sets the sink's level enabler to leveler.
func WithLeveler(leveler levelSetter) SinkOption {
	return func(conf *sinkConfig) {
		conf.level = leveler
	}
}

// WithGlobalRedaction adds values to be redacted from logs.
func WithGlobalRedaction() SinkOption {
	return func(conf *sinkConfig) {
		conf.redactor = globalRedactor
	}
}

// WithSuppressCaller prevents the sink being configured from logging any caller information, irrespective of any other
// logger settings.
func WithSuppressCaller() SinkOption {
	return func(conf *sinkConfig) {
		conf.suppressCaller = true
	}
}

// ToLogger converts the logr.Logger into a legacy *log.Logger.
func ToLogger(l logr.Logger) *log.Logger {
	return slog.NewLogLogger(logr.ToSlogHandler(l), slog.LevelInfo)
}

// ToSlogger converts the logr.Logger into a *slog.Logger.
func ToSlogger(l logr.Logger) *slog.Logger {
	return slog.New(logr.ToSlogHandler(l))
}

// newCore is a helper function that creates a default sinkConfig,
// applies the options, then creates a zapcore.Core.
func newCore(
	defaultEncoder zapcore.Encoder,
	defaultSink zapcore.WriteSyncer,
	defaultLevel levelSetter,
	opts ...SinkOption,
) zapcore.Core {
	conf := sinkConfig{
		encoder: defaultEncoder,
		sink:    defaultSink,
		level:   defaultLevel,
	}
	for _, f := range opts {
		f(&conf)
	}
	core := zapcore.NewCore(
		conf.encoder,
		conf.sink,
		conf.level,
	)

	if conf.redactor != nil {
		core = NewRedactionCore(core, conf.redactor)
	}

	if conf.suppressCaller {
		core = &suppressCallerCore{Core: core}
	}

	return core
}
