package logstash

import (
	"errors"
	"fmt"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type Document struct {
	ID        string
	Timestamp string
	Message   string
}

func fetchIndexNames(client *elasticsearch.TypedClient) ([]string, error) {
	allowNoIndices := true

	req := esapi.IndicesGetRequest{
		Index:          []string{"*"},
		AllowNoIndices: &allowNoIndices,
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	data, err := bodyToJSON(res.Body)
	if err != nil {
		return nil, err
	}

	names := make([]string, len(data))
	count := 0

	for indexName, _ := range data {
		names[count] = indexName
		count++
	}

	return names, nil
}

func fetchIndexDocumentCount(
	client *elasticsearch.TypedClient,
	indexName string,
) (int, error) {
	req := esapi.CountRequest{
		Index: []string{indexName},
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()
	data, err := bodyToJSON(res.Body)
	if err != nil {
		return 0, err
	}

	rawCount, found := data["count"]
	if !found {
		return 0, errors.New("No count in response")
	}

	count, ok := rawCount.(float64)
	if !ok {
		return 0, fmt.Errorf("Could not coerce '%s' to float", rawCount)
	}

	return int(count), nil
}

func createPITSearch(client *elasticsearch.TypedClient, indexName string) (string, error) {
	req := esapi.OpenPointInTimeRequest{
		Index:     []string{indexName},
		KeepAlive: "1m",
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	data, err := bodyToJSON(res.Body)
	if err != nil {
		return "", err
	}

	pitID, found := data["id"].(string)
	if !found {
		return "", errors.New("No count in response")
	}

	return pitID, nil
}

func fetchIndexDocuments(
	client *elasticsearch.TypedClient,
	indexName string,
	offset int,
) ([]Document, error) {
	pitID, err := createPITSearch(client, indexName)
	if err != nil {
		return nil, err
	}

	// [TODO] Look at restricting fields to just the log message
	allowPartialSearchResults := true
	body := fmt.Sprintf(`
		{
      "pit": {
        "id":  "%s",
        "keep_alive": "1m"
      },
			"search_after": [%d"]
		}`,
		pitID,
		offset,
	)

	req := esapi.SearchRequest{
		AllowPartialSearchResults: &allowPartialSearchResults,
		Body:                      strings.NewReader(body),
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	searchResults, err := bodyToJSON(res.Body)
	if err != nil {
		return nil, err
	}

	documents := make([]Document, 0)

	topLevelHits, ok := searchResults["hits"].(map[string]any)
	if !ok {
		return documents, nil
	}

	hits, ok := topLevelHits["hits"].([]any)
	if !ok {
		return documents, nil
	}

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

	return documents, nil
}

func fetchIndexDocumentCounts(
	client *elasticsearch.TypedClient,
) ([]IndexDocumentCount, error) {
	counts := []IndexDocumentCount{}

	indexNames, err := fetchIndexNames(client)
	if err != nil {
		return nil, err
	}

	for _, name := range indexNames {
		c, err := fetchIndexDocumentCount(client, name)
		if err != nil {
			return nil, err
		}

		counts = append(counts, IndexDocumentCount{IndexName: name, DocumentCount: c})
	}

	return counts, nil
}
