package logstash

import (
	"errors"
	"fmt"
	"strings"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func (s *Source) fetchIndexNames() ([]string, error) {
	allowNoIndices := true

	req := esapi.IndicesGetRequest{
		Index:          []string{"*"},
		AllowNoIndices: &allowNoIndices,
	}

	res, err := req.Do(context.Background(), s.client)
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

func (s *Source) fetchIndexDocumentCount(indexName string) (int, error) {
	req := esapi.CountRequest{
		Index: []string{indexName},
	}

	res, err := req.Do(context.Background(), s.client)
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

func (s *Source) createPITSearch(indexName string) (string, error) {
	req := esapi.OpenPointInTimeRequest{
		Index:     []string{indexName},
		KeepAlive: "1m",
	}

	res, err := req.Do(context.Background(), s.client)
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

func (s *Source) fetchIndexDocuments(indexName string) ([]string, error) {
	pitID, err := s.createPITSearch(indexName)
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
      }
		}`,
		pitID,
	)

	req := esapi.SearchRequest{
		AllowPartialSearchResults: &allowPartialSearchResults,
		Body:                      strings.NewReader(body),
	}

	res, err := req.Do(context.Background(), s.client)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	searchResults, err := bodyToJSON(res.Body)
	if err != nil {
		return nil, err
	}

	messages := make([]string, 0)

	topLevelHits := searchResults["hits"].(map[string]any)
	hits, ok := topLevelHits["hits"].([]any)
	if !ok {
		return messages, nil
	}

	for _, jsonHit := range hits {
		hit, ok := jsonHit.(map[string]any)
		if !ok {
			continue
		}

		source, ok := hit["_source"].(map[string]any)
		if !ok {
			continue
		}
		message, ok := source["message"].(string)
		if !ok {
			continue
		}
		messages = append(messages, message)
	}

	return messages, nil
}
