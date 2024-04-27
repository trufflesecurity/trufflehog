//go:build integration
// +build integration

package logstash

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/testcontainers/testcontainers-go"
	elasticcontainer "github.com/testcontainers/testcontainers-go/modules/elasticsearch"
)

const USER string = "elastic" // This is hardcoded in the container

func buildTestClient(
	ec *elasticcontainer.ElasticsearchContainer,
) (*elasticsearch.TypedClient, error) {
	return elasticsearch.NewTypedClient(elasticsearch.Config{
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
		indexNames, err := fetchIndexNames(ctx, es)
		if err != nil {
			t.Error(err)
		}

		if len(indexNames) != 0 {
			t.Errorf("wanted 0 indexNames, got %d\n", len(indexNames))
		}
	})

	indexName := gofakeit.Word()
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
			indexNames, err := fetchIndexNames(ctx, es)
			if err != nil {
				t.Error(err)
			}

			if len(indexNames) != 1 {
				t.Errorf("wanted 1 indexNames, got %d\n", len(indexNames))
			}

			if indexNames[0] != indexName {
				t.Errorf("wanted index name \"%s\", got %s", indexName, indexNames[0])
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
			indexDocumentCount, err := fetchIndexDocumentCount(ctx, es, indexName)
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
			docRange := IndexDocumentRange{
				Index: Index{
					Name:          indexName,
					PrimaryShards: []int{0},
					DocumentCount: 1,
				},
				Offset: 0,
			}

			docs, err := FetchIndexDocuments(ctx, es, &docRange)
			if err != nil {
				t.Error(err)
			}

			if len(docs) != 1 {
				t.Fatalf("wanted 1 document, got %d\n", len(docs))
			}

			doc := docs[0]
			if doc.Timestamp != now.Format(time.RFC3339) {
				t.Errorf(
					"wanted timestamp %s, got %s\n",
					now.Format(time.RFC3339),
					doc.Timestamp,
				)
			}
			if doc.Message != payload["message"] {
				t.Errorf(
					"wanted message %s, got %s\n",
					payload["message"],
					doc.Message,
				)
			}
		},
	)
}
