package sources

import "github.com/trufflesecurity/trufflehog/v3/pkg/context"

type jobAttemptIDContextKey struct{}

// ContextWithJobAttemptID associates a caller-defined attempt with source
// progress created by a SourceManager. Zero means unspecified.
func ContextWithJobAttemptID(ctx context.Context, attemptID JobAttemptID) context.Context {
	return context.WithValue(ctx, jobAttemptIDContextKey{}, attemptID)
}

func jobAttemptIDFromContext(ctx context.Context) JobAttemptID {
	attemptID, _ := ctx.Value(jobAttemptIDContextKey{}).(JobAttemptID)
	return attemptID
}
