package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type FilterParams struct {
	indexPattern   string
	queryJSON      string
	sinceTimestamp string
}

func (fp *FilterParams) Query() (map[string]any, error) {
	query := make(map[string]any)

	if fp.queryJSON != "" {
		err := json.Unmarshal([]byte(fp.queryJSON), &query)
		if err != nil {
			return nil, err
		}
	}

	if fp.sinceTimestamp != "" {
		gte := make(map[string]string)
		gte["gte"] = fp.sinceTimestamp

		timestamp := make(map[string]map[string]string)
		timestamp["timestamp"] = gte

		query["range"] = timestamp
	}

	return query, nil
}

type PointInTime struct {
	ID        string `json:"id"`
	KeepAlive string `json:"keep_alive"`
}

type SearchRequestBody struct {
	PIT         PointInTime    `json:"pit"`
	Sort        []string       `json:"sort"`
	SearchAfter *int           `json:"search_after,omitempty"`
	Query       map[string]any `json:"query,omitempty"`
}

type Document struct {
	id        string
	timestamp string
	message   string
}

type Index struct {
	name          string
	primaryShards []int
	documentCount int
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

func getShardListPreference(primaryShards []int) string {
	if len(primaryShards) == 0 {
		return ""
	}

	shardList := &strings.Builder{}
	shardList.WriteString("_shards:")

	for i, n := range primaryShards {
		if i > 0 {
			shardList.WriteString(",")
		}
		shardList.WriteString(strconv.Itoa(n))
	}

	return shardList.String()
}

func fetchIndexNames(
	ctx context.Context,
	client *es.TypedClient,
	indexPattern string,
) ([]string, error) {
	req := esapi.IndicesGetRequest{
		Index: []string{indexPattern},
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
	client *es.TypedClient,
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
	client *es.TypedClient,
	filterParams FilterParams,
) (int, error) {
	query, err := filterParams.Query()
	if err != nil {
		return 0, err
	}

	body, err := json.Marshal(query)
	if err != nil {
		return 0, err
	}

	req := esapi.CountRequest{
		Index: []string{filterParams.indexPattern},
		Body:  strings.NewReader(string(body)),
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
	client *es.TypedClient,
	docSearch *DocumentSearch,
) (string, error) {
	req := esapi.OpenPointInTimeRequest{
		Index:      []string{docSearch.Index.name},
		KeepAlive:  "1m",
		Preference: getShardListPreference(docSearch.Index.primaryShards),
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

// Fetches a range of documents from an index
func fetchIndexDocuments(
	ctx context.Context,
	client *es.TypedClient,
	docSearch *DocumentSearch,
) ([]Document, error) {
	/* [TODO]

	It's possible that between counting and fetching documents that the count's
	changed; in particular a document could have been deleted. That won't cause
	issues with our bookkeeping here as we'll see we didn't get more hits for a
	search and bail (this short circuits the loop invariant), but it could
	result in us scanning a document multiple times. I think this isn't a
	problem, but need to validate with Truffle.
	*/
	pitID, err := createPITSearch(ctx, client, docSearch)
	if err != nil {
		return nil, err
	}

	documents := make([]Document, 0)

	allowPartialSearchResults := false
	documentsFetched := 0

	for documentsFetched < docSearch.documentCount {
		searchReqBody := SearchRequestBody{
			PIT: PointInTime{
				ID:        pitID,
				KeepAlive: "1m",
			},
			Sort: []string{"_doc"},
		}

		// "search_after" really means "after": the specified ID isn't included in
		// the results. This means 0 is a valid value here, but that interacts
		// badly with Go's "omitempty" which will omit it. So we use a pointer and
		// only specify it if the value > -1.
		searchAfter := ((docSearch.offset + documentsFetched) - 1)
		if searchAfter > -1 {
			searchReqBody.SearchAfter = &searchAfter
		}

		query, err := docSearch.filterParams.Query()
		if err != nil {
			return nil, err
		}

		searchReqBody.Query = query

		body, err := json.MarshalIndent(searchReqBody, "", "  ")
		if err != nil {
			return nil, err
		}

		req := esapi.SearchRequest{
			AllowPartialSearchResults: &allowPartialSearchResults,
			Body:                      strings.NewReader(string(body)),
			SourceIncludes:            []string{"@timestamp", "message"},
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

		if len(hits) == 0 {
			break
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
					id:        id,
					timestamp: timestamp,
					message:   message,
				},
			)
		}
	}

	return documents, nil
}

// Returns an array of all of the indices in an Elasticsearch cluster.
func fetchIndices(
	ctx context.Context,
	client *es.TypedClient,
	filterParams FilterParams,
) ([]Index, error) {
	indices := []Index{}

	indexNames, err := fetchIndexNames(ctx, client, filterParams.indexPattern)
	if err != nil {
		return nil, err
	}

	indexPrimaryShards, err := fetchIndexPrimaryShards(ctx, client, indexNames)
	if err != nil {
		return nil, err
	}

	for indexName, primaryShards := range indexPrimaryShards {
		c, err := fetchIndexDocumentCount(ctx, client, filterParams)
		if err != nil {
			return nil, err
		}

		indices = append(
			indices,
			Index{
				name:          indexName,
				primaryShards: primaryShards,
				documentCount: c,
			},
		)
	}

	return indices, nil
}
