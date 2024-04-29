//go:build integration
// +build integration

package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/testcontainers/testcontainers-go"
	elasticcontainer "github.com/testcontainers/testcontainers-go/modules/elasticsearch"
)

const USER string = "elastic" // This is hardcoded in the container

func buildTestClient(
	ec *elasticcontainer.ElasticsearchContainer,
) (*es.TypedClient, error) {
	return es.NewTypedClient(es.Config{
		Addresses: []string{ec.Settings.Address},
		Username:  USER,
		Password:  ec.Settings.Password,
		CACert:    ec.Settings.CACert,
	})
}

func TestSource_ElasticAPI(t *testing.T) {
	ctx := context.Background()
	ec, err := elasticcontainer.RunContainer(
		ctx,
		testcontainers.WithImage("docker.elastic.co/elasticsearch/elasticsearch:8.9.0"),
	)
	if err != nil {
		log.Fatalf("Could not start elasticsearch: %s", err)
	}
	defer func() {
		if err := ec.Terminate(ctx); err != nil {
			log.Fatalf("Could not stop elasticsearch: %s", err)
		}
	}()

	es, err := buildTestClient(ec)

	if err != nil {
		log.Fatalf("error creating the elasticsearch client: %s", err)
	}

	t.Run("New server contains no indexes", func(t *testing.T) {
		indexNames, err := fetchIndexNames(ctx, es, "*")
		if err != nil {
			t.Error(err)
		}

		if len(indexNames) != 0 {
			t.Errorf("wanted 0 indexNames, got %d\n", len(indexNames))
		}
	})

	indexName := gofakeit.Word()
	indexName2 := gofakeit.Word()
	now := time.Now()

	payload := make(map[string]string)
	payload["message"] = gofakeit.SentenceSimple()
	payload["@timestamp"] = now.Format(time.RFC3339)

	jsonMessage, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	req := esapi.IndexRequest{
		Index:   indexName,
		Body:    bytes.NewReader(jsonMessage),
		Refresh: "true",
	}

	res, err := req.Do(ctx, es)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	t.Run(
		"Adding a document to a new index creates a single index",
		func(t *testing.T) {
			indexNames, err := fetchIndexNames(ctx, es, "*")
			if err != nil {
				t.Error(err)
			}

			if len(indexNames) != 1 {
				t.Fatalf("wanted 1 indexNames, got %d\n", len(indexNames))
			}

			if indexNames[0] != indexName {
				t.Errorf("wanted index name \"%s\", got %s", indexName, indexNames[0])
			}
		},
	)

	nowAgain := time.Now()
	payload2 := make(map[string]string)
	payload2["message"] = gofakeit.SentenceSimple()
	payload2["@timestamp"] = nowAgain.Format(time.RFC3339)

	jsonMessage, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	req = esapi.IndexRequest{
		Index:   indexName2,
		Body:    bytes.NewReader(jsonMessage),
		Refresh: "true",
	}

	res, err = req.Do(ctx, es)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	t.Run(
		"Unspecified indexPattern fetches no indices",
		func(t *testing.T) {
			indices, err := fetchIndices(ctx, es, FilterParams{})
			if err != nil {
				t.Fatal(err)
			}

			if len(indices) != 0 {
				t.Errorf("wanted 0 indices, got %d\n", len(indices))
			}
		},
	)

	t.Run(
		"Indices have the correct document count",
		func(t *testing.T) {
			indices, err := fetchIndices(ctx, es, FilterParams{indexPattern: "*"})
			if err != nil {
				t.Fatal(err)
			}

			if len(indices) != 2 {
				t.Errorf("wanted 2 indices, got %d\n", len(indices))
			}

			if indices[0].documentCount != 1 {
				t.Errorf(
					"wanted documentCount of 1 in 1st index, got %d\n",
					indices[0].documentCount,
				)
			}

			if indices[1].documentCount != 1 {
				t.Errorf(
					"wanted documentCount of 1 in 2nd index, got %d\n",
					indices[1].documentCount,
				)
			}
		},
	)

	t.Run(
		"A single unit of work has the correct max document count",
		func(t *testing.T) {
			indices, err := fetchIndices(ctx, es, FilterParams{indexPattern: "*"})
			if err != nil {
				t.Fatal(err)
			}

			unitsOfWork := DistributeDocumentScans(1, indices, FilterParams{indexPattern: "*"})

			if len(unitsOfWork) != 1 {
				t.Fatalf("wanted 1 unit of work, got %d\n", len(unitsOfWork))
			}

			if len(unitsOfWork[0].documentSearches) != 2 {
				t.Fatalf(
					"wanted 1 doc search in 1st unit of work, got %d\n",
					len(unitsOfWork[0].documentSearches),
				)
			}

			if unitsOfWork[0].documentSearches[0].documentCount != 1 {
				t.Errorf(
					"wanted max document count of 1 in unit of work's 1st doc search, got %d\n",
					unitsOfWork[0].documentSearches[0].documentCount,
				)
			}

			if unitsOfWork[0].documentSearches[1].documentCount != 1 {
				t.Errorf(
					"wanted max document count of 1 in unit of work's 2nd doc search, got %d\n",
					unitsOfWork[0].documentSearches[1].documentCount,
				)
			}
		},
	)

	t.Run(
		"Multiple units of work have the correct max document count",
		func(t *testing.T) {
			indices, err := fetchIndices(ctx, es, FilterParams{indexPattern: "*"})
			if err != nil {
				t.Fatal(err)
			}

			unitsOfWork := DistributeDocumentScans(2, indices, FilterParams{indexPattern: "*"})

			if len(unitsOfWork) != 2 {
				t.Fatalf("wanted 2 units of work, got %d\n", len(unitsOfWork))
			}

			if len(unitsOfWork[0].documentSearches) != 1 {
				t.Fatalf(
					"wanted 1 doc search in 1st unit of work, got %d\n",
					len(unitsOfWork[0].documentSearches),
				)
			}

			if len(unitsOfWork[1].documentSearches) != 1 {
				t.Fatalf(
					"wanted 1 doc search in 2nd unit of work, got %d\n",
					len(unitsOfWork[0].documentSearches),
				)
			}

			if unitsOfWork[0].documentSearches[0].documentCount != 1 {
				t.Errorf(
					"wanted max document count of 1 in 1st unit of work's doc search, got %d\n",
					unitsOfWork[0].documentSearches[0].documentCount,
				)
			}

			if unitsOfWork[1].documentSearches[0].documentCount != 1 {
				t.Errorf(
					"wanted max document count of 1 in 2nd unit of work's doc search, got %d\n",
					unitsOfWork[1].documentSearches[0].documentCount,
				)
			}
		},
	)

	t.Run(
		"New indexes have only 1 primary shard",
		func(t *testing.T) {
			primaryShardsByIndex, err := fetchIndexPrimaryShards(ctx, es, []string{indexName})
			if err != nil {
				t.Error(err)
			}

			if len(primaryShardsByIndex) != 1 {
				t.Errorf("wanted 1 primary shard count, got %d\n", len(primaryShardsByIndex))
			}

			primaryShards, found := primaryShardsByIndex[indexName]
			if !found {
				t.Errorf("index \"%s\" not found in primary shard counts", indexName)
			}

			if len(primaryShards) != 1 {
				t.Errorf("wanted primary shard count of 1, got %d\n", primaryShards)
			}
		},
	)

	t.Run(
		"Adding a document to a new index creates a document count of 1",
		func(t *testing.T) {
			indexDocumentCount, err := fetchIndexDocumentCount(
				ctx,
				es,
				indexName,
				make(map[string]any),
			)
			if err != nil {
				t.Error(err)
			}

			if indexDocumentCount != 1 {
				t.Errorf("wanted 1 document count, got %d\n", indexDocumentCount)
			}
		},
	)

	t.Run(
		"Stored document matches passed values",
		func(t *testing.T) {
			docSearch := DocumentSearch{
				Index: Index{
					name:          indexName,
					primaryShards: []int{0},
					documentCount: 1,
				},
				offset:       0,
				filterParams: FilterParams{},
			}

			docs, err := fetchIndexDocuments(ctx, es, &docSearch)
			if err != nil {
				t.Error(err)
			}

			if len(docs) != 1 {
				t.Fatalf("wanted 1 document, got %d\n", len(docs))
			}

			doc := docs[0]
			if doc.timestamp != now.Format(time.RFC3339) {
				t.Errorf(
					"wanted timestamp %s, got %s\n",
					now.Format(time.RFC3339),
					doc.timestamp,
				)
			}
			if doc.message != payload["message"] {
				t.Errorf(
					"wanted message %s, got %s\n",
					payload["message"],
					doc.message,
				)
			}
		},
	)
}
