package logstash

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_LOGSTASH

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	log      logr.Logger
	verify   bool
	client   *elasticsearch.TypedClient
}

func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

func (s *Source) Init(
	aCtx context.Context,
	name string,
	jobId sources.JobID,
	sourceId sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	var conn sourcespb.Logstash
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	cfg := elasticsearch.Config{
		CloudID: conn.CloudId,
		APIKey:  conn.ApiKey,
	}

	client, err := elasticsearch.NewTypedClient(cfg)
	if err != nil {
		return err
	}

	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.log = aCtx.Logger()
	s.verify = verify
	s.client = client

	return nil
}

func (s *Source) Chunks(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	targets ...sources.ChunkingTarget,
) error {
	// Plan of attack:
	// - Build a map of indices and document counts
	//   - Fetch the indices
	//   - Iterate through them and update the document count in the map
	//   - A unit of work is a 3-tuple (indexName, firstDoc, lastDoc)
	// -
	return nil
}

func (s *Source) GetProgress() *sources.Progress {
	return nil
}
