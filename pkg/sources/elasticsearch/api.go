package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

const PAGE_SIZE = 10

type IndexStatus int

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
	name                   string
	documentCount          int
	latestTimestamp        time.Time
	latestTimestampLastRun time.Time
	latestDocumentIDs      []string
	lock                   sync.RWMutex
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
	timestampRangeQueryClause := make(map[string]any)

	if fp.queryJSON != "" {
		err := json.Unmarshal([]byte(fp.queryJSON), &timestampRangeQueryClause)
		if err != nil {
			return nil, err
		}
	}

	if !latestTimestamp.IsZero() {
		gte := make(map[string]string)
		gte["gte"] = latestTimestamp.Format(time.RFC3339)

		timestamp := make(map[string]map[string]string)
		timestamp["@timestamp"] = gte

		timestampRangeQueryClause["range"] = timestamp
	} else if fp.sinceTimestamp != "" {
		gte := make(map[string]string)
		gte["gte"] = fp.sinceTimestamp

		timestamp := make(map[string]map[string]string)
		timestamp["@timestamp"] = gte

		timestampRangeQueryClause["range"] = timestamp
	}

	query := make(map[string]any)
	query["query"] = timestampRangeQueryClause

	return query, nil
}

func NewIndex() *Index {
	return &Index{}
}

func (i *Index) DocumentAlreadySeen(document *Document) bool {
	parsedTimestamp, err := time.Parse(time.RFC3339, document.timestamp)
	if err != nil {
		return false
	}

	// We mutate the index in different ways depending on whether the timestamp
	// is newer, equal, or older than the its current latest timestamp, so
	// everything at this point must be write synchronized.
	i.lock.Lock()
	defer i.lock.Unlock()

	if parsedTimestamp.After(i.latestTimestamp) {
		i.latestTimestamp = parsedTimestamp
		i.latestDocumentIDs = i.latestDocumentIDs[:0]
		return false
	}

	if i.latestTimestamp.Equal(i.latestTimestampLastRun) &&
		slices.Contains(i.latestDocumentIDs, document.id) {
		return true
	}

	i.latestDocumentIDs = append(i.latestDocumentIDs, document.id)
	return false
}

func (i *Index) UpdateLatestTimestampLastRun() {
	i.lock.Lock()
	i.latestTimestampLastRun = i.latestTimestamp
	i.lock.Unlock()
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
		Index:     []string{docSearch.index.name},
		KeepAlive: "1m",
	}

	data, err := makeElasticSearchRequest(ctx, client, req)
	if err != nil {
		return "", err
	}

	pitID, ok := data["id"].(string)
	if !ok {
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
	processDocument func(document *Document) error,
) (int, error) {
	pitID, err := createPITForSearch(ctx, client, docSearch)
	if err != nil {
		return 0, err
	}

	documentsFetched := 0
	documentsProcessed := 0
	sort := []int{}

	for documentsProcessed < docSearch.documentCount {
		searchReqBody := SearchRequestBody{
			PIT: PointInTime{
				ID:        pitID,
				KeepAlive: "1m",
			},
			Sort: []string{"_shard_doc"},
		}

		query, err := docSearch.filterParams.Query(docSearch.index.latestTimestamp)
		if err != nil {
			return 0, err
		}

		searchReqBody.Query = query["query"].(map[string]any)

		if len(sort) > 0 {
			searchReqBody.SearchAfter = sort
		}

		body, err := json.MarshalIndent(searchReqBody, "", "  ")
		if err != nil {
			return 0, err
		}

		req := esapi.SearchRequest{
			Body: strings.NewReader(string(body)),
		}

		// If we've yet to reach our offset, or if we're still in the "skip" phase
		// of scanning, don't actually fetch any document bodies.
		skipCount := docSearch.offset + docSearch.skipCount
		processingDocuments := documentsFetched+PAGE_SIZE > skipCount
		if processingDocuments {
			req.SourceIncludes = []string{"@timestamp", "message"}
		} else {
			req.SourceExcludes = []string{"*"}
			req.SearchType = "query_then_fetch"
		}

		searchResults, err := makeElasticSearchRequest(ctx, client, req)
		if err != nil {
			return 0, err
		}

		topLevelHits, ok := searchResults["hits"].(map[string]any)
		if !ok {
			apiErr, ok := searchResults["error"].(map[string]any)
			if ok {
				return 0, fmt.Errorf("Error fetching search results: %v\n", apiErr)
			}
			continue
		}

		hits, ok := topLevelHits["hits"].([]any)
		if !ok {
			continue
		}

		if len(hits) == 0 {
			break
		}

		for _, jsonHit := range hits {
			documentsFetched++

			hit, ok := jsonHit.(map[string]any)
			if !ok {
				continue
			}

			jsonSort, ok := hit["sort"].([]any)
			if !ok {
				continue
			}

			sort = sort[:0]
			for _, elem := range jsonSort {
				sort = append(sort, int(elem.(float64)))
			}

			if documentsFetched <= skipCount {
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

			document := Document{
				id:        id,
				timestamp: timestamp,
				message:   message,
			}

			if err = processDocument(&document); err != nil {
				return 0, nil
			}

			documentsProcessed++
		}
	}

	return documentsProcessed, nil
}

// Returns the number of documents processed within these indices
func (indices *Indices) GetProcessedDocumentCount() int {
	indices.lock.RLock()
	processedDocumentsCount := indices.processedDocumentsCount
	indices.lock.RUnlock()

	return processedDocumentsCount
}

// Adds documents processed to the count, used for progress
func (indices *Indices) UpdateProcessedDocumentCount(additionalDocumentsProcessed int) {
	indices.lock.Lock()
	indices.processedDocumentsCount += additionalDocumentsProcessed
	indices.lock.Unlock()
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
		index, ok := indicesByName[name]
		if ok {
			newIndicesByName[name] = index
		} else {
			index = NewIndex()
			index.name = name
			newIndicesByName[name] = index
		}
	}

	for _, indexName := range indexNames {
		// This can't be an index we don't know about because we passed indexNames
		index := newIndicesByName[indexName]

		query, err := indices.filterParams.Query(index.latestTimestamp)
		if err != nil {
			return err
		}

		documentCount, err := fetchIndexDocumentCount(ctx, client, indexName, query)
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
