package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/elasticsearch"
)

// ScanElasticsearch scans a Elasticsearch installation.
func (e *Engine) ScanElasticsearch(ctx context.Context, c sources.ElasticsearchConfig) error {
	connection := &sourcespb.Elasticsearch{
		Nodes:          c.Nodes,
		Username:       c.Username,
		Password:       c.Password,
		CloudId:        c.CloudID,
		ApiKey:         c.APIKey,
		ServiceToken:   c.ServiceToken,
		IndexPattern:   c.IndexPattern,
		QueryJson:      c.QueryJSON,
		SinceTimestamp: c.SinceTimestamp,
		BestEffortScan: c.BestEffortScan,
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Elasticsearch connection")
		return err
	}

	sourceName := "trufflehog - Elasticsearch"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, elasticsearch.SourceType)

	elasticsearchSource := &elasticsearch.Source{}
	if err := elasticsearchSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, elasticsearchSource)
	return err
}
