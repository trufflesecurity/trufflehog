package mailgun

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// DomainsJSON is /domains API response
type DomainsJSON struct {
	Items      []Domain `json:"items"`
	TotalCount int      `json:"total_count"`
}

// Domain is a single mailgun domain details
type Domain struct {
	ID         string `json:"id"`
	URL        string `json:"name"`
	IsDisabled bool   `json:"is_disabled"`
	Type       string `json:"type"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
}

// KeysJSON is /v1/keys API response
type KeysJSON struct {
	Items      []Key `json:"items"`
	TotalCount int   `json:"total_count"`
}

// Key is a single mailgun Key details
type Key struct {
	ID        string `json:"id"`
	Requester string `json:"requestor"`
	UserName  string `json:"user_name"`
	Role      string `json:"role"`
	Type      string `json:"kind"`
	ExpiresAt string `json:"expires_at"`
}

// getDomains list all domains
func getDomains(client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	var domainsJSON DomainsJSON

	req, err := http.NewRequest("GET", "https://api.mailgun.net/v4/domains", nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth("api", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid Mailgun API key")
	}

	err = json.NewDecoder(resp.Body).Decode(&domainsJSON)
	if err != nil {
		return err
	}

	// populate secretInfo with domains
	secretInfo.Domains = append(secretInfo.Domains, domainsJSON.Items...)

	return nil
}

func getKeys(client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	var keysJSON KeysJSON

	req, err := http.NewRequest("GET", "https://api.mailgun.net/v1/keys", nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth("api", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid Mailgun API key")
	}

	err = json.NewDecoder(resp.Body).Decode(&keysJSON)
	if err != nil {
		return err
	}

	// populate secretInfo with key details
	for _, key := range keysJSON.Items {
		// filter the exact key which we are analyzing
		// ID is actually the suffix of actual apiKeys
		if strings.Contains(apiKey, key.ID) {
			keyToSecretInfo(key, secretInfo)
		}
	}

	return nil
}

func keyToSecretInfo(key Key, secretInfo *SecretInfo) {
	secretInfo.ID = key.ID
	if key.UserName != "" {
		secretInfo.UserName = key.UserName
	} else {
		secretInfo.UserName = key.Requester
	}

	secretInfo.Role = key.Role
	secretInfo.Type = key.Type
	if secretInfo.ExpiresAt != "" {
		secretInfo.ExpiresAt = key.ExpiresAt
	} else {
		secretInfo.ExpiresAt = "Never"
	}
}
