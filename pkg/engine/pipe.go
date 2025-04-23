package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/pipe"
)

// ScanPipeInput scans input that is piped into the application
func (e *Engine) ScanPipeInput(ctx context.Context, c sources.PipeConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Pipe{}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal pipe connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - pipe"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, pipe.SourceType)

	pipeSource := &pipe.Source{}
	if err := pipeSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, pipeSource)
}
