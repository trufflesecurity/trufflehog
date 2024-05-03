package elasticsearch

import (
	"fmt"
	"sync"
	"time"

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
	esConfig     es.Config
	filterParams FilterParams
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

	s.ctx = aCtx
	s.log = aCtx.Logger()

	esConfig := es.Config{}

	if conn.Username != "" {
		esConfig.Username = conn.Username
	}

	if conn.Password != "" {
		esConfig.Password = conn.Password
	}

	if conn.CloudId != "" {
		esConfig.CloudID = conn.CloudId
	}

	if conn.ApiKey != "" {
		esConfig.APIKey = conn.ApiKey
	}

	if conn.ServiceToken != "" {
		esConfig.ServiceToken = conn.ServiceToken
	}

	s.esConfig = esConfig

	if conn.IndexPattern == "" {
		s.filterParams.indexPattern = "*"
	} else {
		s.filterParams.indexPattern = conn.IndexPattern
	}

	s.filterParams.queryJSON = conn.QueryJson
	s.filterParams.sinceTimestamp = conn.SinceTimestamp

	client, err := s.buildElasticClient()
	if err != nil {
		return err
	}

	s.client = client

	return nil
}

func (s *Source) buildElasticClient() (*es.TypedClient, error) {
	return es.NewTypedClient(s.esConfig)
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
	indices := Indices{filterParams: &s.filterParams}

	err := indices.Update(s.ctx, s.client)
	if err != nil {
		return err
	}

	unitsOfWork := distributeDocumentScans(s.concurrency, indices)
	totalDocumentsProcessed := 0
	lock := sync.RWMutex{}

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

			for _, docSearch := range uow.documentSearches {
				documentsFetched, err := processSearchedDocuments(
					s.ctx,
					client,
					&docSearch,
					func(document *Document) error {
						parsedTimestamp, err := time.Parse(time.RFC3339, document.timestamp)
						if err == nil {
							if parsedTimestamp.After(docSearch.index.latestTimestamp) {
								docSearch.index.latestTimestamp = parsedTimestamp
							}
						}

						chunk := sources.Chunk{
							SourceType: s.Type(),
							SourceName: s.name,
							SourceID:   s.SourceID(),
							JobID:      s.JobID(),
							SourceMetadata: &source_metadatapb.MetaData{
								Data: &source_metadatapb.MetaData_Elasticsearch{
									Elasticsearch: &source_metadatapb.Elasticsearch{
										Index:      sanitizer.UTF8(docSearch.index.name),
										DocumentId: sanitizer.UTF8(document.id),
										Timestamp:  sanitizer.UTF8(document.timestamp),
									},
								},
							},
							Verify: s.verify,
						}

						chunk.Data = []byte(document.message)

						return common.CancellableWrite(ctx, chunksChan, &chunk)
					},
				)
				if err != nil {
					return err
				}

				// [TODO] Warn if documentsFetched != docSearch.documentCount

				lock.Lock()
				totalDocumentsProcessed += docSearch.documentCount
				lock.Unlock()

				// When we use the Elastic API in this way, we can't tell it to only
				// return a specific number of documents. We can only say "return a
				// page of documents after this offset". So we might reach the limit
				// of how many documents we're supposed to process with this worker
				// in the middle of a page, so check for that here.
				//
				// (We could use the API in a different way to get a precise number
				// of documents back, but that use is limited to 10000 documents
				// which we could well exceed)
				if totalDocumentsProcessed >= uow.documentCount {
					s.SetProgressComplete(
						uow.maxDocumentCount,
						uow.maxDocumentCount,
						fmt.Sprintf("Scanned %d total documents", uow.maxDocumentCount),
						"",
					)
					break
				}
				s.SetProgressComplete(
					totalDocumentsProcessed,
					uow.maxDocumentCount,
					fmt.Sprintf(
						"Finished scanning %d documents from index %s",
						documentsFetched,
						docSearch.index.name,
					),
					"",
				)
			}

			return nil
		})
	}

	return nil
}
