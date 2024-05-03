package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

type IndexStatus int

const (
	indexRemoved IndexStatus = iota
	indexExists
	indexAdded
)

type FilterParams struct {
	indexPattern   string
	queryJSON      string
	sinceTimestamp string
}

type PointInTime struct {
	ID        string `json:"id"`
	KeepAlive string `json:"keep_alive"`
}

type SearchRequestBody struct {
	PIT         PointInTime    `json:"pit"`
	Sort        []string       `json:"sort"`
	SearchAfter []int          `json:"search_after,omitempty"`
	Query       map[string]any `json:"query,omitempty"`
}

type Document struct {
	id        string
	timestamp string
	message   string
}

type Index struct {
	name            string
	primaryShards   []int
	documentCount   int
	latestTimestamp time.Time
}

type Indices struct {
	indices      []Index
	filterParams *FilterParams
}

type elasticSearchRequest interface {
	Do(providedCtx context.Context, transport esapi.Transport) (*esapi.Response, error)
}

func (fp *FilterParams) Query(latestTimestamp time.Time) (map[string]any, error) {
	query := make(map[string]any)

	if fp.queryJSON != "" {
		err := json.Unmarshal([]byte(fp.queryJSON), &query)
		if err != nil {
			return nil, err
		}
	}

	if !latestTimestamp.IsZero() {
		gte := make(map[string]string)
		gte["gte"] = latestTimestamp.Format(time.RFC3339)

		timestamp := make(map[string]map[string]string)
		timestamp["timestamp"] = gte

		query["range"] = timestamp
	} else if fp.sinceTimestamp != "" {
		gte := make(map[string]string)
		gte["gte"] = fp.sinceTimestamp

		timestamp := make(map[string]map[string]string)
		timestamp["timestamp"] = gte

		query["range"] = timestamp
	}

	return query, nil
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
	indexName string,
	query map[string]any,
) (int, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return 0, err
	}

	req := esapi.CountRequest{
		Index: []string{indexName},
	}

	if len(body) > 0 {
		req.Body = strings.NewReader(string(body))
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

func createPITForSearch(
	ctx context.Context,
	client *es.TypedClient,
	docSearch *DocumentSearch,
) (string, error) {
	req := esapi.OpenPointInTimeRequest{
		Index:      []string{docSearch.index.name},
		KeepAlive:  "1m",
		Preference: getShardListPreference(docSearch.index.primaryShards),
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

// Processes documents fetched by a search, returns the number of documents
// fetched.
func processSearchedDocuments(
	ctx context.Context,
	client *es.TypedClient,
	docSearch *DocumentSearch,
	sendDocument func(document *Document) error,
) (int, error) {
	pitID, err := createPITForSearch(ctx, client, docSearch)
	if err != nil {
		fmt.Println("-1")
		return 0, err
	}

	documentsFetched := 0

	fmt.Printf("docs fetched/count: %d/%d\n", documentsFetched, docSearch.documentCount)

	for documentsFetched < docSearch.documentCount {
		searchReqBody := SearchRequestBody{
			PIT: PointInTime{
				ID:        pitID,
				KeepAlive: "1m",
			},
			Sort: []string{"_doc"},
		}

		searchAfter := ((docSearch.offset + documentsFetched) - 1)
		if searchAfter > -1 {
			searchReqBody.SearchAfter = []int{searchAfter}
		}

		query, err := docSearch.filterParams.Query(docSearch.index.latestTimestamp)
		if err != nil {
			fmt.Println("a")
			return 0, err
		}

		searchReqBody.Query = query

		body, err := json.MarshalIndent(searchReqBody, "", "  ")
		if err != nil {
			fmt.Println("b")
			return 0, err
		}

		req := esapi.SearchRequest{
			Body:           strings.NewReader(string(body)),
			SourceIncludes: []string{"@timestamp", "message"},
		}

		searchResults, err := makeElasticSearchRequest(ctx, client, req)
		if err != nil {
			fmt.Println("c")
			return 0, err
		}

		topLevelHits, ok := searchResults["hits"].(map[string]any)
		if !ok {
			fmt.Println("1")
			// [TODO] This almost certainly means there were errors in the response we should
			//		    probably surface somehow
			continue
		}

		hits, ok := topLevelHits["hits"].([]any)
		if !ok {
			fmt.Println("2")
			continue
		}

		if len(hits) == 0 {
			fmt.Println("No hits")
			break
		}

		fmt.Printf("Got %d hits\n", len(hits))

		documentsFetched += len(hits)

		for _, jsonHit := range hits {
			hit, ok := jsonHit.(map[string]any)
			if !ok {
				fmt.Println("3")
				continue
			}

			id, ok := hit["_id"].(string)
			if !ok {
				fmt.Println("4")
				continue
			}

			source, ok := hit["_source"].(map[string]any)
			if !ok {
				fmt.Println("5")
				continue
			}

			timestamp, ok := source["@timestamp"].(string)
			if !ok {
				fmt.Println("6")
				continue
			}

			message, ok := source["message"].(string)
			if !ok {
				fmt.Println("7")
				continue
			}

			document := Document{
				id:        id,
				timestamp: timestamp,
				message:   message,
			}
			if err = sendDocument(&document); err != nil {
				fmt.Println("8")
				return 0, nil
			}
		}
	}

	fmt.Println("buddy")
	return documentsFetched, nil
}

// Updates a set of indices from an Elasticsearch cluster. If an index has been
// deleted it will be removed; if it's been added it'll be added; if its
// document count has changed (based on filterParams and latestTimestamp) it'll
// be updated.
func (indices *Indices) Update(
	ctx context.Context,
	client *es.TypedClient,
) error {
	indexNames, err := fetchIndexNames(ctx, client, indices.filterParams.indexPattern)
	if err != nil {
		return err
	}

	indicesByName := make(map[string]*Index)
	if indices.indices != nil {
		for _, index := range indices.indices {
			indicesByName[index.name] = &index
		}
	}

	newIndicesByName := make(map[string]*Index)
	for _, name := range indexNames {
		index, found := indicesByName[name]
		if found {
			newIndicesByName[name] = index
		} else {
			newIndicesByName[name] = &Index{name: name}
		}
	}

	indexPrimaryShards, err := fetchIndexPrimaryShards(ctx, client, indexNames)
	if err != nil {
		return err
	}

	for name, primaryShards := range indexPrimaryShards {
		// This can't be an index we don't know about because we passed indexNames
		index := newIndicesByName[name]
		index.primaryShards = primaryShards

		query, err := indices.filterParams.Query(index.latestTimestamp)
		if err != nil {
			return err
		}

		documentCount, err := fetchIndexDocumentCount(ctx, client, name, query)
		if err != nil {
			return err
		}

		index.documentCount = documentCount
	}

	indices.indices = make([]Index, 0, len(newIndicesByName))
	for _, index := range newIndicesByName {
		indices.indices = append(indices.indices, *index)
	}

	return nil
}
