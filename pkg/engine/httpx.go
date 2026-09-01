package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/httpx"
)

// ScanHttpx scans the response bodies captured in httpx JSONL output.
func (e *Engine) ScanHttpx(ctx context.Context, c sources.HttpxConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Httpx{
		Paths:               c.Paths,
		Base64Body:          c.Base64Body,
		IncludeHeadlessBody: c.IncludeHeadlessBody,
		MaxRecordBytes:      c.MaxRecordBytes,
	}

	var conn anypb.Any
	if err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{}); err != nil {
		ctx.Logger().Error(err, "failed to marshal httpx connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - httpx"
	sourceID, jobID, err := e.sourceManager.GetIDs(ctx, sourceName, httpx.SourceType)
	if err != nil {
		ctx.Logger().Error(err, "failed to get IDs from source manager")
		return sources.JobProgressRef{}, err
	}

	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	source := &httpx.Source{}
	if err := source.Init(ctx, sourceName, jobID, sourceID, true, &conn, concurrency); err != nil {
		return sources.JobProgressRef{}, err
	}

	return e.sourceManager.EnumerateAndScan(ctx, sourceName, source)
}
