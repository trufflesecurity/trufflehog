package engine

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// withSourceFields adds the source fields to the context. Call it before Init,
// so lines a source logs during Init say which source and job they came from too.
// The source manager adds the same fields later for the scan, but skips any
// already set here.
func withSourceFields(
	ctx context.Context,
	sourceName string,
	sourceType sourcespb.SourceType,
	sourceID sources.SourceID,
	jobID sources.JobID,
) context.Context {
	return context.WithValues(ctx,
		"source_name", sourceName,
		"source_type", sourceType.String(),
		"source_id", sourceID,
		"job_id", jobID,
	)
}
