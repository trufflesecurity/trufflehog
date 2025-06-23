package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/stdin"
)

// ScanStdinInput scans input that is piped into the application
func (e *Engine) ScanStdinInput(ctx context.Context, c sources.StdinConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Stdin{}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal stdin connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - stdin"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, stdin.SourceType)

	stdinSource := &stdin.Source{}
	if err := stdinSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, stdinSource)
}
