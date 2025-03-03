package airtablepat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/common"
)

type AirtableRecordsResponse struct {
	Records []common.AirtableEntity `json:"records"`
}

func fetchAirtableRecords(token string, baseID string, tableID string) ([]common.AirtableEntity, error) {
	endpoint, exists := getEndpoint(common.ListRecordsEndpoint)
	if !exists {
		return nil, fmt.Errorf("endpoint for ListRecordsEndpoint does not exist")
	}
	url := strings.Replace(strings.Replace(endpoint.URL, "{baseID}", baseID, -1), "{tableID}", tableID, -1)
	resp, err := common.CallAirtableAPI(token, "GET", url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable records, status: %d", resp.StatusCode)
	}

	var recordsResponse AirtableRecordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&recordsResponse); err != nil {
		return nil, err
	}

	return recordsResponse.Records, nil
}
