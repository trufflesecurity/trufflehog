package common

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Recover handles panics and reports to Sentry.
func Recover(ctx context.Context) {
	if err := recover(); err != nil {
		panicStack := string(debug.Stack())
		if eventID := sentry.CurrentHub().Recover(err); eventID != nil {
			ctx.Logger().Info("panic captured", "event_id", *eventID)
		}
		ctx.Logger().Error(fmt.Errorf("panic"), "recovered from panic",
			"stack-trace", panicStack,
			"recover", err,
		)
		if !sentry.Flush(time.Second * 5) {
			ctx.Logger().Info("sentry flush failed")
		}
	}
}

// RecoverWithExit handles panics and reports to Sentry before exiting.
func RecoverWithExit(ctx context.Context) {
	if err := recover(); err != nil {
		panicStack := string(debug.Stack())
		if eventID := sentry.CurrentHub().Recover(err); eventID != nil {
			ctx.Logger().Info("panic captured", "event_id", *eventID)
		}
		ctx.Logger().Error(fmt.Errorf("panic"), "recovered from panic before exiting",
			"stack-trace", panicStack,
			"recover", err,
		)
		if !sentry.Flush(time.Second * 5) {
			ctx.Logger().Info("sentry flush failed")
		}
		os.Exit(1)
	}
}
