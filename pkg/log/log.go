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

type logConfig struct {
	core    zapcore.Core
	cleanup func() error
	err     error
}

// New creates a new log object with the provided configurations. If no sinks
// are provided, a no-op sink will be used. Returns the logger and a cleanup
// function that should be executed before the program exits.
func New(service string, configs ...logConfig) (logr.Logger, func() error) {
	var cores []zapcore.Core
	var cleanupFuncs []func() error

	// create cores for the logger
	for _, config := range configs {
		if config.err != nil {
			continue
		}
		cores = append(cores, config.core)
		if config.cleanup != nil {
			cleanupFuncs = append(cleanupFuncs, config.cleanup)
		}
	}
	// create logger
	zapLogger := zap.New(zapcore.NewTee(cores...))
	cleanupFuncs = append(cleanupFuncs, zapLogger.Sync)
	logger := zapr.NewLogger(zapLogger).WithName(service)

	// report the errors we encountered in the configs
	for _, config := range configs {
		if config.err != nil {
			logger.Error(config.err, "error configuring logger")
		}
	}

	return logger, firstErrorFunc(cleanupFuncs...)
}

// WithSentry adds sentry integration to the logger. This configuration may
// fail, in which case, sentry will not be added and execution will continue
// normally.
func WithSentry(opts sentry.ClientOptions, tags map[string]string) logConfig {
	client, err := sentry.NewClient(opts)
	if err != nil {
		return logConfig{err: err}
	}

	// create sentry core
	cfg := zapsentry.Configuration{
		Tags:              tags,
		Level:             zapcore.ErrorLevel,
		EnableBreadcrumbs: true,
		BreadcrumbLevel:   zapcore.InfoLevel,
	}
	core, err := zapsentry.NewCore(cfg, zapsentry.NewSentryClientFromClient(client))
	if err != nil {
		return logConfig{err: err}
	}

	return logConfig{
		core: core,
		cleanup: func() error {
			sentry.Flush(5 * time.Second)
			return nil
		},
	}
}

type sinkConfig struct {
	encoder  zapcore.Encoder
	sink     zapcore.WriteSyncer
	level    levelSetter
	redactor *dynamicRedactor
}

// WithJSONSink adds a JSON encoded output to the logger.
func WithJSONSink(sink io.Writer, opts ...func(*sinkConfig)) logConfig {
	return newCoreConfig(
		zapcore.NewJSONEncoder(defaultEncoderConfig()),
		zapcore.Lock(zapcore.AddSync(sink)),
		globalLogLevel,
		opts...,
	)
}

// WithConsoleSink adds a console-style output to the logger.
func WithConsoleSink(sink io.Writer, opts ...func(*sinkConfig)) logConfig {
	return newCoreConfig(
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
func WithCore(core zapcore.Core) logConfig {
	return logConfig{core: core}
}

// AddSentry initializes a sentry client and extends an existing
// logr.Logger with the hook.
func AddSentry(l logr.Logger, opts sentry.ClientOptions, tags map[string]string) (logr.Logger, func() error, error) {
	return AddSink(l, WithSentry(opts, tags))
}

// AddSink extends an existing logr.Logger with a new sink. It returns the new logr.Logger, a cleanup function, and an
// error.
//
// The new sink will not inherit any of the existing logger's key-value pairs. Key-value pairs can be added to the new
// sink specifically by passing them to this function.
func AddSink(l logr.Logger, sink logConfig, keysAndValues ...any) (logr.Logger, func() error, error) {
	if sink.err != nil {
		return l, nil, sink.err
	}

	// New key-value pairs cannot be ergonomically added directly to cores. logr has code to do it, but that code is not
	// exported. Rather than replicating it ourselves, we indirectly use it by creating a temporary logger for the new
	// core, adding the key-value pairs to the temporary logger, and then extracting the temporary logger's modified
	// core.
	newSinkLogger := zapr.NewLogger(zap.New(sink.core))
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
	zapLogger = zapLogger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return zapcore.NewTee(core, newSinkCore)
	}))
	return zapr.NewLogger(zapLogger), firstErrorFunc(zapLogger.Sync, sink.cleanup), nil
}

func SuppressCallerEmission(l logr.Logger) (logr.Logger, error) {
	zapLogger, err := getZapLogger(l)
	if err != nil {
		return l, err
	}

	zapLogger = zapLogger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return &suppressCallerCore{Core: core}
	}))
	return zapr.NewLogger(zapLogger), nil
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
func WithLevel(level int8) func(*sinkConfig) {
	return WithLeveler(
		// Zap's levels get more verbose as the number gets smaller, as explained
		// by zapr here: https://github.com/go-logr/zapr#increasing-verbosity
		// For example setting the level to -2 below, means log.V(2) will be enabled.
		zap.NewAtomicLevelAt(zapcore.Level(-level)),
	)
}

// WithLeveler sets the sink's level enabler to leveler.
func WithLeveler(leveler levelSetter) func(*sinkConfig) {
	return func(conf *sinkConfig) {
		conf.level = leveler
	}
}

// WithGlobalRedaction adds values to be redacted from logs.
func WithGlobalRedaction() func(*sinkConfig) {
	return func(conf *sinkConfig) {
		conf.redactor = globalRedactor
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

// firstErrorFunc is a helper function that returns a function that executes
// all provided args and returns the first error, if any.
func firstErrorFunc(fs ...func() error) func() error {
	return func() error {
		var firstErr error = nil
		for _, f := range fs {
			if f == nil {
				continue
			}
			if err := f(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
}

// newCoreConfig is a helper function that creates a default sinkConfig,
// applies the options, then creates a zapcore.Core.
func newCoreConfig(
	defaultEncoder zapcore.Encoder,
	defaultSink zapcore.WriteSyncer,
	defaultLevel levelSetter,
	opts ...func(*sinkConfig),
) logConfig {
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

	if conf.redactor == nil {
		return logConfig{core: core}
	}

	return logConfig{core: NewRedactionCore(core, conf.redactor)}
}
