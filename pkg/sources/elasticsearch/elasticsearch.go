package elasticsearch

import (
	"fmt"
	"time"

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/go-errors/errors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
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
	name           string
	sourceId       sources.SourceID
	jobId          sources.JobID
	concurrency    int
	verify         bool
	esConfig       es.Config
	filterParams   FilterParams
	bestEffortScan bool
	client         *es.TypedClient
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

	esConfig := es.Config{Logger: apiLogger{}}

	if len(conn.Nodes) > 0 {
		esConfig.Addresses = conn.Nodes
	}

	if conn.Username != "" {
		esConfig.Username = conn.Username
	}

	if conn.Password != "" {
		esConfig.Password = conn.Password
		log.RedactGlobally(conn.Password)
	}

	if conn.CloudId != "" {
		esConfig.CloudID = conn.CloudId
	}

	if conn.ApiKey != "" {
		esConfig.APIKey = conn.ApiKey
		log.RedactGlobally(conn.ApiKey)
	}

	if conn.ServiceToken != "" {
		esConfig.ServiceToken = conn.ServiceToken
		log.RedactGlobally(conn.ServiceToken)
	}

	s.esConfig = esConfig

	if conn.IndexPattern == "" {
		s.filterParams.indexPattern = "*"
	} else {
		s.filterParams.indexPattern = conn.IndexPattern
	}

	s.filterParams.queryJSON = conn.QueryJson
	s.filterParams.sinceTimestamp = conn.SinceTimestamp

	s.bestEffortScan = conn.BestEffortScan

	client, err := es.NewTypedClient(s.esConfig)
	if err != nil {
		return err
	}

	s.client = client

	aCtx.Logger().V(1).Info("Elasticsearch source initialized",
		"nodes", len(conn.Nodes),
		"cloud_id_set", conn.CloudId != "",
		"auth_method", authMethod(&conn),
		"index_pattern", s.filterParams.indexPattern,
		"query_set", conn.QueryJson != "",
		"since_timestamp", conn.SinceTimestamp,
		"best_effort_scan", s.bestEffortScan,
		"concurrency", s.concurrency,
	)

	return nil
}

// authMethod names the credential type for logs, never the credential.
func authMethod(conn *sourcespb.Elasticsearch) string {
	switch {
	case conn.ServiceToken != "":
		return "service_token"
	case conn.ApiKey != "":
		return "api_key"
	case conn.Username != "" || conn.Password != "":
		return "basic"
	default:
		return "none"
	}
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

	for pass := 1; ; pass++ {
		workerPool := new(errgroup.Group)
		workerPool.SetLimit(s.concurrency)

		previousDocumentCount := indices.documentCount
		err := indices.Update(ctx, s.client)
		if err != nil {
			return err
		}
		ctx.Logger().V(1).Info("Listed indices",
			"pass", pass,
			"indices", len(indices.indices),
			"documents", indices.documentCount,
		)

		// Don't burn up the ES API with rapid requests if there's no work to do
		if previousDocumentCount > 0 && indices.documentCount == 0 {
			duration, _ := time.ParseDuration("5s")
			ctx.Logger().V(4).Info("No new documents, waiting", "wait", duration)
			time.Sleep(duration)
			continue
		}

		// The scanCoverageRate is documentsScanned / documentsAdded. If it's < 1 we
		// need each DocumentSearch to skip some records.
		scanCoverageRate := 1.0
		if previousDocumentCount > 0 && indices.documentCount > 0 && previousDocumentCount < indices.documentCount {
			scanCoverageRate =
				float64(previousDocumentCount) / float64(indices.documentCount)
			ctx.Logger().V(1).Info("Scan coverage below 100%, skipping documents to catch up",
				"coverage_rate", scanCoverageRate,
				"previous_documents", previousDocumentCount,
				"documents", indices.documentCount,
			)
		}

		unitsOfWork := distributeDocumentScans(&indices, s.concurrency, scanCoverageRate)

		for outerUOWIndex, outerUOW := range unitsOfWork {
			uowIndex := outerUOWIndex
			uow := outerUOW

			workerPool.Go(func() error {
				workerCtx := context.WithValues(ctx, "worker", uowIndex)

				// Give each worker its own client
				client, err := es.NewTypedClient(s.esConfig)
				if err != nil {
					return err
				}

				uowDocumentsProcessed := 0

				for _, docSearch := range uow.documentSearches {
					indexCtx := context.WithValues(workerCtx, "index", docSearch.index.name)
					indexCtx.Logger().V(2).Info("Scanning index",
						"offset", docSearch.offset,
						"documents", docSearch.documentCount,
						"skip", docSearch.skipCount,
					)

					documentsProcessed, err := processSearchedDocuments(
						indexCtx,
						client,
						&docSearch,
						func(document *Document) error {
							if docSearch.index.DocumentAlreadySeen(document) {
								indexCtx.Logger().V(4).Info("Skipping document",
									"document_id", document.id,
									"reason", "already scanned",
								)
								return nil
							}
							indexCtx.Logger().V(3).Info("Scanning document", "document_id", document.id)

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
								SourceVerify: s.verify,
							}

							chunk.Data = []byte(document.message)

							return common.CancellableWrite(ctx, chunksChan, &chunk)
						},
					)
					if err != nil {
						return err
					}

					indexCtx.Logger().V(2).Info("Finished scanning index", "scanned", documentsProcessed)

					if expected := docSearch.documentCount - docSearch.skipCount; documentsProcessed != expected {
						indexCtx.Logger().V(4).Info("Scanned document count differs from expected",
							"expected", expected,
							"scanned", documentsProcessed,
						)
					}

					uowDocumentsProcessed += documentsProcessed
					indices.UpdateProcessedDocumentCount(documentsProcessed)
					s.SetProgressComplete(
						indices.GetProcessedDocumentCount(),
						indices.documentCount,
						fmt.Sprintf(
							"[Worker %d] Scanned %d documents from index %s",
							uowIndex,
							documentsProcessed,
							docSearch.index.name,
						),
						"",
					)

					// When we use the Elastic API in this way, we can't tell
					// it to only return a specific number of documents. We can
					// only say "return a page of documents after this offset".
					// So we might have reached the limit of how many documents
					// we're supposed to process with this worker in the middle
					// of a page, so check for that here.
					//
					// (We could use the API in a different way to get a
					// precise number of documents back, but that use is
					// limited to 10000 documents which we could well exceed)
					if uowDocumentsProcessed >= uow.documentCount {
						break
					}

					docSearch.index.UpdateLatestTimestampLastRun()
				}

				return nil
			})
		}

		err = workerPool.Wait()
		// A cancelled scan fails its workers too, that is not an error to report.
		if err != nil && ctx.Err() == nil {
			ctx.Logger().Error(err, "Failed to scan documents", "pass", pass)
		}

		if !s.bestEffortScan {
			break
		}
	}

	return nil
}
