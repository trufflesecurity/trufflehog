package log

import (
	"sort"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Global, default log level control.
	globalLogLevel levelSetter = zap.NewAtomicLevel()
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

// findLevel probes a logr.Logger to figure out what level it is at via binary
// search. We only search [0, 128), so worst case is ~7 checks.
func findLevel(logger logr.Logger) int8 {
	sink := logger.GetSink()
	return int8(sort.Search(128, func(i int) bool {
		return !sink.Enabled(i)
	}) - 1)
}
