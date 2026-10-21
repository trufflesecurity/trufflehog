// Package logtest has helpers for testing log output.
package logtest

import (
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
)

// DebugContext returns a Context with debug logging turned on, plus the logs written to it.
//
// The logger works like a source's logger when debug is turned on for that source: its sink is set to V(0), and
// context.WithLogLevel raises it to log.DebugLevel. Use it to check that a source writes the debug logs you expect,
// and that it does not write values that must never be logged.
//
//	ctx, logs := logtest.DebugContext()
//	_ = s.Init(ctx, ...)
//	assert.Equal(t, 1, logs.FilterMessage("listing repositories").Len())
func DebugContext() (context.Context, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
	return context.WithLogLevel(ctx, log.DebugLevel), logs
}
