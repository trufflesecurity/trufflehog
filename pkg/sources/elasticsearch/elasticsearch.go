package elasticsearch

import (
	"fmt"
	"log"

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_ELASTICSEARCH

type Source struct {
	name         string
	sourceId     sources.SourceID
	jobId        sources.JobID
	concurrency  int
	verify       bool
	cloudId      string
	apiKey       string
	indexPattern string
	ctx          context.Context
	client       *es.TypedClient
	log          logr.Logger
	sources.Progress
}

// Init returns an initialized Elasticsearch source
func (s *Source) Init(
	aCtx context.Context,
	name string,
	jobId sources.JobID,
	sourceId sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	var conn sourcespb.Elasticsearch
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.concurrency = concurrency
	s.verify = verify
	s.cloudId = conn.CloudId
	s.apiKey = conn.ApiKey
	s.ctx = aCtx
	s.log = aCtx.Logger()

	if conn.IndexPattern == "" {
		s.indexPattern = "*"
	} else {
		s.indexPattern = conn.IndexPattern
	}

	client, err := s.buildElasticClient()
	if err != nil {
		return err
	}

	s.client = client

	return nil
}

func (s *Source) buildElasticClient() (*es.TypedClient, error) {
	return BuildElasticClient(s.cloudId, s.apiKey)
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

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	targets ...sources.ChunkingTarget,
) error {
	indices, err := FetchIndices(s.ctx, s.client, s.indexPattern)
	if err != nil {
		return err
	}

	unitsOfWork := DistributeDocumentScans(s.concurrency, indices)

	workerPool := new(errgroup.Group)
	workerPool.SetLimit(s.concurrency)
	defer func() { _ = workerPool.Wait() }()

	for _, outerUOW := range unitsOfWork {
		uow := outerUOW

		workerPool.Go(func() error {
			// Give each worker its own client
			client, err := s.buildElasticClient()
			if err != nil {
				return err
			}

			for _, indexDocumentRange := range uow.IndexDocumentRanges {
				// We should never set out to process a range of documents if the unit
				// of work's document count is 0; if that's the case we goofed
				// accounting somewhere. Log a warning in that case.
				if uow.DocumentCount == 0 {
					log.Println("Accounting error: doc count is 0 but pages remain")
				}

				documents, err := FetchIndexDocuments(s.ctx, client, &indexDocumentRange)
				if err != nil {
					return err
				}

				for _, document := range documents {
					chunk := sources.Chunk{
						SourceType: s.Type(),
						SourceName: s.name,
						SourceID:   s.SourceID(),
						JobID:      s.JobID(),
						SourceMetadata: &source_metadatapb.MetaData{
							Data: &source_metadatapb.MetaData_Elasticsearch{
								Elasticsearch: &source_metadatapb.Elasticsearch{
									Index:      sanitizer.UTF8(indexDocumentRange.Name),
									DocumentId: sanitizer.UTF8(document.ID),
									Timestamp:  sanitizer.UTF8(document.Timestamp),
								},
							},
						},
						Verify: s.verify,
					}

					chunk.Data = []byte(document.Message)

					if err := common.CancellableWrite(ctx, chunksChan, &chunk); err != nil {
						return err
					}
					uow.DocumentCount--
					indexDocumentRange.Offset++

					// When we use the Elastic API in this way, we can't tell it to only
					// return a specific number of documents. We can only say "return a
					// page of documents after this offset". So we might reach the limit
					// of how many documents we're supposed to process with this worker
					// in the middle of a page, so check for that here.
					//
					// (We could use the API in a different way to get a precise number
					// of documents back, but that use is limited to 10000 documents
					// which we could well exceed)
					if uow.DocumentCount == 0 {
						s.SetProgressComplete(
							uow.MaxDocumentCount,
							uow.MaxDocumentCount,
							fmt.Sprintf("Scanned %d total documents", uow.MaxDocumentCount),
							"",
						)
						break
					}
					s.SetProgressComplete(
						uow.MaxDocumentCount-uow.DocumentCount,
						uow.MaxDocumentCount,
						fmt.Sprintf(
							"Scanned %d documents from index %s",
							len(documents),
							indexDocumentRange.Name,
						),
						"",
					)
				}
			}

			return nil
		})
	}

	return nil
}
