package logstash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type Document struct {
	ID        string
	Timestamp string
	Message   string
}

type Index struct {
	Name          string
	PrimaryShards []int
	DocumentCount int
}

type elasticSearchRequest interface {
	Do(providedCtx context.Context, transport esapi.Transport) (*esapi.Response, error)
}

func makeElasticSearchRequest(
	ctx context.Context,
	transport esapi.Transport,
	req elasticSearchRequest,
) (map[string]any, error) {
	res, err := req.Do(ctx, transport)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	rawData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	data := make(map[string]any)

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func getShardListPreference(i *Index) string {
	if len(i.PrimaryShards) == 0 {
		return ""
	}

	shardList := &strings.Builder{}
	shardList.WriteString("_shards:")

	for i, n := range i.PrimaryShards {
		if i > 0 {
			shardList.WriteString(",")
		}
		shardList.WriteString(strconv.Itoa(n))
	}

	return shardList.String()
}

func fetchIndexNames(
	ctx context.Context,
	client *elasticsearch.TypedClient,
) ([]string, error) {
	allowNoIndices := true

	req := esapi.IndicesGetRequest{
		Index:          []string{"*"},
		AllowNoIndices: &allowNoIndices,
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(data))
	count := 0

	for indexName := range data {
		names[count] = indexName
		count++
	}

	return names, nil
}

func fetchIndexPrimaryShards(
	ctx context.Context,
	client *elasticsearch.TypedClient,
	indexNames []string,
) (map[string][]int, error) {
	primaryShards := make(map[string][]int)

	req := esapi.SearchShardsRequest{
		Index: indexNames,
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return nil, err
	}

	shardArrays := data["shards"].([]any)

	for _, jsonShardArray := range shardArrays {
		shardArray := jsonShardArray.([]any)
		shard := shardArray[0].(map[string]any)
		shardIndex := shard["index"].(string)
		isPrimary := shard["primary"].(bool)
		if !isPrimary {
			continue
		}
		shardNumber := int(shard["shard"].(float64))
		_, found := primaryShards[shardIndex]
		if !found {
			primaryShards[shardIndex] = []int{}
		}
		primaryShards[shardIndex] = append(primaryShards[shardIndex], shardNumber)
	}

	return primaryShards, nil
}

func fetchIndexDocumentCount(
	ctx context.Context,
	client *elasticsearch.TypedClient,
	indexName string,
) (int, error) {
	req := esapi.CountRequest{
		Index: []string{indexName},
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return 0, err
	}

	rawCount, found := data["count"]
	if !found {
		return 0, errors.New("No count in response")
	}

	count, ok := rawCount.(float64)
	if !ok {
		return 0, fmt.Errorf("Failed to coerce '%s' to float64", rawCount)
	}

	return int(count), nil
}

func createPITSearch(
	ctx context.Context,
	client *elasticsearch.TypedClient,
	docRange *IndexDocumentRange,
) (string, error) {
	req := esapi.OpenPointInTimeRequest{
		Index:      []string{docRange.Name},
		KeepAlive:  "1m",
		Preference: getShardListPreference(&docRange.Index),
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return "", err
	}

	pitID, found := data["id"].(string)
	if !found {
		return "", errors.New("No count in response")
	}

	return pitID, nil
}

// Builds a new Elasticsearch client
func BuildElasticClient(
	cloudID, apiKey string,
) (*elasticsearch.TypedClient, error) {
	return elasticsearch.NewTypedClient(elasticsearch.Config{
		CloudID: cloudID,
		APIKey:  apiKey,
	})
}

// Fetches a range of documents from an index
func FetchIndexDocuments(
	ctx context.Context,
	client *elasticsearch.TypedClient,
	docRange *IndexDocumentRange,
) ([]Document, error) {
	pitID, err := createPITSearch(ctx, client, docRange)
	if err != nil {
		return nil, err
	}

	// [TODO] See if it's possible to restrict the returned fields to just what
	// 				we want
	allowPartialSearchResults := true
	body := ""
	documents := make([]Document, 0)
	documentsFetched := 0

	for documentsFetched < docRange.DocumentCount {
		searchAfter := docRange.Offset + documentsFetched

		if searchAfter > 0 {
			body = fmt.Sprintf(`
				{
					"pit": {
						"id":  "%s",
						"keep_alive": "1m"
					},
					"sort": ["_doc"],
					"search_after": [%d]
				}`,
				pitID,
				// "search_after" really means "after"; the specified index isn't
				// included. You can think of it as -1-based indexing.
				searchAfter-1,
			)
		} else {
			body = fmt.Sprintf(`
				{
					"pit": {
						"id":  "%s",
						"keep_alive": "1m"
					},
					"sort": ["_doc"]
				}`,
				pitID,
			)
		}

		req := esapi.SearchRequest{
			AllowPartialSearchResults: &allowPartialSearchResults,
			Body:                      strings.NewReader(body),
		}

		searchResults, err := makeElasticSearchRequest(ctx, client, req)
		if err != nil {
			return nil, err
		}

		topLevelHits, ok := searchResults["hits"].(map[string]any)
		if !ok {
			continue
		}

		hits, ok := topLevelHits["hits"].([]any)
		if !ok {
			continue
		}

		documentsFetched += len(hits)

		for _, jsonHit := range hits {
			hit, ok := jsonHit.(map[string]any)
			if !ok {
				continue
			}

			id, ok := hit["_id"].(string)
			if !ok {
				continue
			}

			source, ok := hit["_source"].(map[string]any)
			if !ok {
				continue
			}

			timestamp, ok := source["@timestamp"].(string)
			if !ok {
				continue
			}

			message, ok := source["message"].(string)
			if !ok {
				continue
			}

			documents = append(
				documents,
				Document{
					ID:        id,
					Timestamp: timestamp,
					Message:   message,
				},
			)
		}
	}

	return documents, nil
}

// Returns an array of all of the indices in an Elasticsearch cluster.
func FetchIndices(
	ctx context.Context,
	client *elasticsearch.TypedClient,
) ([]Index, error) {
	indices := []Index{}

	indexNames, err := fetchIndexNames(ctx, client)
	if err != nil {
		return nil, err
	}

	indexPrimaryShards, err := fetchIndexPrimaryShards(ctx, client, indexNames)
	if err != nil {
		return nil, err
	}

	for indexName, primaryShards := range indexPrimaryShards {
		c, err := fetchIndexDocumentCount(ctx, client, indexName)
		if err != nil {
			return nil, err
		}

		indices = append(
			indices,
			Index{
				Name:          indexName,
				PrimaryShards: primaryShards,
				DocumentCount: c,
			},
		)
	}

	return indices, nil
}
