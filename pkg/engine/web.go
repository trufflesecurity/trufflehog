package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/web"
)

// ScanWeb scans a given web connection.
func (e *Engine) ScanWeb(ctx context.Context, c sources.WebConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Web{
		Urls:  c.URLs,
		Crawl: c.Crawl,
		Depth: int64(c.Depth),
		Delay: int64(c.Delay),
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal web connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - web"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, web.SourceType)

	webSource := &web.Source{}
	if err := webSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, webSource)
}
