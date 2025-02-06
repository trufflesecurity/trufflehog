//go:generate generate_permissions permissions.yaml permissions.go airtable
package airtable

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeAirtable }

type AirtableUserInfo struct {
	ID     string   `json:"id"`
	Email  *string  `json:"email,omitempty"`
	Scopes []string `json:"scopes"`
}

type AirtableBases struct {
	Bases []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"bases"`
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, errors.New("token not found in credInfo")
	}

	userInfo, err := fetchAirtableUserInfo(token)
	if err != nil {
		return nil, err
	}

	var basesInfo *AirtableBases
	if hasScope(userInfo.Scopes, PermissionStrings[SchemaBasesRead]) {
		basesInfo, _ = fetchAirtableBases(token)
	}

	return mapToAnalyzerResult(userInfo, basesInfo), nil
}

func fetchAirtableUserInfo(token string) (*AirtableUserInfo, error) {
	url := "https://api.airtable.com/v0/meta/whoami"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable user info, status: %d", resp.StatusCode)
	}

	var userInfo AirtableUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func fetchAirtableBases(token string) (*AirtableBases, error) {
	url := "https://api.airtable.com/v0/meta/bases"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Airtable bases, status: %d", resp.StatusCode)
	}

	var basesInfo AirtableBases
	if err := json.NewDecoder(resp.Body).Decode(&basesInfo); err != nil {
		return nil, err
	}

	return &basesInfo, nil
}

func hasScope(scopes []string, target string) bool {
	for _, scope := range scopes {
		if scope == target {
			return true
		}
	}
	return false
}

func mapToAnalyzerResult(userInfo *AirtableUserInfo, basesInfo *AirtableBases) *analyzers.AnalyzerResult {
	if userInfo == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeAirtable,
	}
	var permissions []analyzers.Permission
	for _, scope := range userInfo.Scopes {
		permissions = append(permissions, analyzers.Permission{Value: scope})
	}
	userResource := analyzers.Resource{
		Name:               userInfo.ID,
		FullyQualifiedName: userInfo.ID,
		Type:               "user",
		Metadata:           map[string]any{},
	}

	if userInfo.Email != nil {
		userResource.Metadata["email"] = *userInfo.Email
	}

	result.Bindings = analyzers.BindAllPermissions(userResource, permissions...)

	if basesInfo != nil {
		for _, base := range basesInfo.Bases {
			resource := analyzers.Resource{
				Name:               base.Name,
				FullyQualifiedName: base.ID,
				Type:               "base",
			}
			result.UnboundedResources = append(result.UnboundedResources, resource)
		}
	}

	return &result
}
