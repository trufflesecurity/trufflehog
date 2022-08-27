package common

import (
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Recover recovers panics and reports to Sentry before exiting
func Recover(ctx context.Context) {
	if err := recover(); err != nil {
		panicStack := string(debug.Stack())
		eventID := sentry.CurrentHub().Recover(err)
		if eventID != nil {
			ctx.Logger().Info("panic captured", "event_id", *eventID)
		}
		fmt.Fprint(os.Stderr, panicStack)
		flushed := sentry.Flush(time.Second * 5)
		if !flushed {
			ctx.Logger().Info("sentry flush failed")
		}
		os.Exit(1)
	}
}
