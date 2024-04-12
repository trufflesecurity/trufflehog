package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/logstash"
)

// ScanLogstash scans a Logstash installation.
func (e *Engine) ScanLogstash(ctx context.Context, c sources.LogstashConfig) error {
	connection := &sourcespb.Logstash{
		CloudId: c.CloudID,
		ApiKey:  c.APIKey,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Logstash connection")
		return err
	}

	sourceName := "trufflehog - Logstash"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, logstash.SourceType)

	logstashSource := &logstash.Source{}
	if err := logstashSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, logstashSource)
	return err
}
