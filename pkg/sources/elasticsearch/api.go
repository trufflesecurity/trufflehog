package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
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
	name             string
	primaryShards    []int
	documentCount    int
	latestTimestamp  time.Time
	latestDocumentID int
	lock             sync.RWMutex
}

type Indices struct {
	indices                 []*Index
	documentCount           int
	processedDocumentsCount int
	filterParams            *FilterParams
	lock                    sync.RWMutex
}

type elasticSearchRequest interface {
	Do(providedCtx context.Context, transport esapi.Transport) (*esapi.Response, error)
}

func (fp *FilterParams) Query(latestTimestamp time.Time) (map[string]any, error) {
	range_ := make(map[string]any)

	if fp.queryJSON != "" {
		err := json.Unmarshal([]byte(fp.queryJSON), &range_)
		if err != nil {
			return nil, err
		}
	}

	if !latestTimestamp.IsZero() {
		gte := make(map[string]string)
		gte["gte"] = latestTimestamp.Format(time.RFC3339)

		timestamp := make(map[string]map[string]string)
		timestamp["@timestamp"] = gte

		range_["range"] = timestamp
	} else if fp.sinceTimestamp != "" {
		gte := make(map[string]string)
		gte["gte"] = fp.sinceTimestamp

		timestamp := make(map[string]map[string]string)
		timestamp["@timestamp"] = gte

		range_["range"] = timestamp
	}

	query := make(map[string]any)
	query["query"] = range_

	return query, nil
}

func NewIndex() *Index {
	return &Index{latestDocumentID: -1}
}

func (i *Index) DocumentIDAlreadySeen(docID int) bool {
	i.lock.Lock()
	defer i.lock.Unlock()

	if docID > i.latestDocumentID {
		i.latestDocumentID = docID
		return false
	}

	return true
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
	size := 0

	req := esapi.SearchRequest{
		Index:      []string{indexName},
		SearchType: "query_then_fetch",
		Size:       &size,
	}

	if len(query["query"].(map[string]any)) > 0 {
		body, err := json.MarshalIndent(query, "", "  ")
		if err != nil {
			return 0, err
		}
		req.Body = strings.NewReader(string(body))
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return 0, err
	}

	hits, ok := data["hits"].(map[string]any)
	if !ok {
		return 0, errors.New("No hits in response")
	}

	total, ok := hits["total"].(map[string]any)
	if !ok {
		return 0, errors.New("No total in hits")
	}

	count, ok := total["value"].(float64)
	if !ok {
		return 0, errors.New("No value in total")
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
		return "", errors.New("No id in response")
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
		fmt.Println("1")
		return 0, err
	}

	documentsFetched := 0

	for documentsFetched < docSearch.documentCount {
		fmt.Printf(
			"documentsFetched/docSearch.documentCount: %d/%d\n",
			documentsFetched,
			docSearch.documentCount,
		)
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
			fmt.Println("2")
			return 0, err
		}

		searchReqBody.Query = query["query"].(map[string]any)

		body, err := json.MarshalIndent(searchReqBody, "", "  ")
		if err != nil {
			fmt.Println("3")
			return 0, err
		}

		fmt.Println("A")

		req := esapi.SearchRequest{
			Body:           strings.NewReader(string(body)),
			SourceIncludes: []string{"@timestamp", "message"},
		}

		fmt.Println("B")

		// If we're still in the "skip" phase of scanning, don't actually fetch the
		// documents.
		percentFetched :=
			float64(documentsFetched+10) / float64(docSearch.documentCount)
		fmt.Printf(
			"percentFetched/docSearch.skipPercent: %f/%f (%d)\n",
			percentFetched,
			docSearch.skipPercent,
			documentsFetched,
		)
		if percentFetched <= docSearch.skipPercent {
			zero := 0
			req.Size = &zero
			req.SearchType = "query_then_fetch"
		}

		fmt.Println("C")

		searchResults, err := makeElasticSearchRequest(ctx, client, req)
		if err != nil {
			fmt.Println("4")
			return 0, err
		}

		fmt.Println("D")

		topLevelHits, ok := searchResults["hits"].(map[string]any)
		if !ok {
			apiErr, ok := searchResults["error"].(map[string]any)
			if ok {
				fmt.Println("5")
				return 0, fmt.Errorf("Error fetching search results: %v\n", apiErr)
			}
			fmt.Printf("No topLevelHits: %v\n", searchResults)
			continue
		}

		fmt.Println("E")

		hits, ok := topLevelHits["hits"].([]any)
		if !ok {
			fmt.Printf("No hits: %v\n", topLevelHits)
			continue
		}

		fmt.Println("F")

		if percentFetched <= docSearch.skipPercent {
			documentsFetched += 10
		} else if len(hits) == 0 {
			break
		} else {
			documentsFetched += len(hits)
		}

		fmt.Println("G")

		for _, jsonHit := range hits {
			hit, ok := jsonHit.(map[string]any)

			if !ok {
				continue
			}

			sort, ok := hit["sort"].([]any)
			if ok {
				docID := -1

				if len(sort) == 1 {
					docID = int(sort[0].(float64))
				} else {
					docID = int(sort[1].(float64))
				}

				if docSearch.index.DocumentIDAlreadySeen(docID) {
					continue
				}
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

			document := Document{
				id:        id,
				timestamp: timestamp,
				message:   message,
			}
			if err = sendDocument(&document); err != nil {
				fmt.Println("6")
				return 0, nil
			}
		}
	}

	return documentsFetched, nil
}

// Returns the number of documents processed within these indices
func (indices *Indices) GetProcessedDocumentCount() int {
	indices.lock.RLock()
	defer indices.lock.RUnlock()

	return indices.processedDocumentsCount
}

// Adds documents processed to the count, used for progress
func (indices *Indices) UpdateProcessedDocumentCount(additionalDocumentsProcessed int) {
	indices.lock.Lock()
	defer indices.lock.Unlock()

	indices.processedDocumentsCount += additionalDocumentsProcessed
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
			indicesByName[index.name] = index
		}
	}

	newIndicesByName := make(map[string]*Index)
	for _, name := range indexNames {
		index, found := indicesByName[name]
		if found {
			newIndicesByName[name] = index
		} else {
			index = NewIndex()
			index.name = name
			newIndicesByName[name] = index
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

	indices.indices = make([]*Index, 0, len(newIndicesByName))
	indices.documentCount = 0
	indices.processedDocumentsCount = 0

	for _, index := range newIndicesByName {
		indices.indices = append(indices.indices, index)
		indices.documentCount += index.documentCount
	}

	return nil
}
