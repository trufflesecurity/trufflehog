package log

import (
	"sync"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TODO: Use a struct to make testing easier.
var (
	// Global, default log level control.
	globalLogLevel levelSetter = zap.NewAtomicLevel()

	// Map of name -> level control for independently setting log levels. A new
	// control is registered via WithNamedLevel. This map is never cleaned up
	// and new entries will overwrite previous values. Currently, this is
	// acceptable behavior because WithNamedLevel is used sparingly.
	globalControls map[string]levelSetter = make(map[string]levelSetter, 16)
	// globalControls is protected (both read and write) by a mutex to make it
	// thread safe. Access is low frequency, so performance is not a concern.
	globalControlsLock sync.Mutex
)

type levelSetter interface {
	zapcore.LevelEnabler
	SetLevel(zapcore.Level)
	Level() zapcore.Level
}

// SetLevel sets the log level for loggers created with the default level
// controller.
func SetLevel(level int8) {
	SetLevelForControl(globalLogLevel, level)
}

// SetLevelForControl sets the log level for a given control.
func SetLevelForControl(control levelSetter, level int8) {
	// Zap's levels get more verbose as the number gets smaller, as explained
	// by zapr here: https://github.com/go-logr/zapr#increasing-verbosity
	// For example setting the level to -2 below, means log.V(2) will be enabled.
	control.SetLevel(zapcore.Level(-level))
}

// SetLevelFor sets the log level for a given named control.
func SetLevelFor(name string, level int8) {
	globalControlsLock.Lock()
	defer globalControlsLock.Unlock()
	if control, ok := globalControls[name]; ok {
		SetLevelForControl(control, level)
		return
	}
	// Create a new control so registering a control with the same name will
	// inherit the existing level.
	newControl := zap.NewAtomicLevel()
	SetLevelForControl(newControl, level)
	globalControls[name] = newControl
}

// AddLeveler adds a log level control to a logr.Logger.
func AddLeveler(l logr.Logger, control levelSetter) (logr.Logger, error) {
	zapLogger, err := getZapLogger(l)
	if err != nil {
		return l, err
	}

	zapLogger = zapLogger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return NewLevelCore(core, control)
	}))
	return zapr.NewLogger(zapLogger), nil
}

// WithNamedLevel creates a child logger with a new name and independent log
// level control (see SetLevelFor). NOTE: The child logger does not inherit the
// parent's log level, but will maintain the existing level if a control exists
// for the name.
func WithNamedLevel(logger logr.Logger, name string) logr.Logger {
	logger = logger.WithName(name)
	leveler := zap.NewAtomicLevel()
	newLogger, err := AddLeveler(logger, leveler)
	if err != nil {
		return logger
	}
	globalControlsLock.Lock()
	defer globalControlsLock.Unlock()
	if currentControl, ok := globalControls[name]; ok {
		leveler.SetLevel(currentControl.Level())
	}
	globalControls[name] = leveler
	return newLogger
}
