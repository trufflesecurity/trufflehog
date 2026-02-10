package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/json_enumerator"
)

// ScanJSONEnumeratorInput scans input that is in JSON Enumerator format
func (e *Engine) ScanJSONEnumeratorInput(
	ctx context.Context,
	c sources.JSONEnumeratorConfig,
) (sources.JobProgressRef, error) {
	connection := &sourcespb.JSONEnumerator{
		Paths: c.Paths,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal JSON enumerator connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - JSON enumerator"
	sourceID, jobID, err := e.sourceManager.GetIDs(ctx, sourceName, json_enumerator.SourceType)
	if err != nil {
		ctx.Logger().Error(err, "failed to get IDs from source manager")
		return sources.JobProgressRef{}, err
	}

	source := &json_enumerator.Source{}
	err = source.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU())
	if err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, source)
}
