package netlify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var (
	apiEndpoints = map[ResourceType]string{
		CurrentUser: "https://api.netlify.com/api/v1/user",
		Token:       "https://app.netlify.com/access-control/bb-api/api/v1/oauth/applications", // undocumented API - return personal tokens with metadata
		Site:        "https://api.netlify.com/api/v1/sites",
		SiteFile:    "https://api.netlify.com/api/v1/sites/%s/files", // require site id
		SiteEnvVar:  "https://api.netlify.com/api/v1/sites/%s/env",   // require site id
	}

	// metadata keys - should always start with resource name
	tokenPersonal  = "personal"
	tokenExpiresAt = "expires_at"
	siteUrl        = "site_url"
	siteAdminUrl   = "site_admin_url"
	siteRepoUrl    = "site_repo_url"
	fileMimeType   = "site_mime_type"
)

// makeNetlifyRequest send the API request to passed url with passed key as personal access token and return response body and status code
func makeNetlifyRequest(client *http.Client, endpoint, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

// captureResources try to capture all the resource that the key can access
func captureResources(client *http.Client, key string, secretInfo *SecretInfo) error {
	var (
		wg             sync.WaitGroup
		errAggWg       sync.WaitGroup
		aggregatedErrs = make([]error, 0)
		errChan        = make(chan error, 1)
	)

	errAggWg.Add(1)
	go func() {
		defer errAggWg.Done()
		for err := range errChan {
			aggregatedErrs = append(aggregatedErrs, err)
		}
	}()

	// helper to launch tasks concurrently.
	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	// capture top level resources
	if err := captureSites(client, key, secretInfo); err != nil {
		return err
	}

	sites := secretInfo.listResourceByType(Site)
	for _, site := range sites {
		launchTask(func() error { return captureSiteFiles(client, key, site, secretInfo) })
		launchTask(func() error { return captureSiteEnvVar(client, key, site, secretInfo) })
	}

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

func captureUserInfo(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[CurrentUser], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user User

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = user

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureTokens(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[Token], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens []token

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens {
			if token.ExpiresAt == "" {
				token.ExpiresAt = "never"
			}

			resource := NetlifyResource{
				ID:   token.ID,
				Name: token.Name,
				Type: Token.String(),
				Metadata: map[string]string{
					tokenExpiresAt: token.ExpiresAt,
					tokenPersonal:  strconv.FormatBool(token.Personal),
				},
			}

			secretInfo.Resources = append(secretInfo.Resources, resource)
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[Token])
	}
}

func captureSites(client *http.Client, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, apiEndpoints[Site], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var sites []site

		if err := json.Unmarshal(respBody, &sites); err != nil {
			return err
		}

		for _, site := range sites {
			secretInfo.appendResource(NetlifyResource{
				ID:   site.SiteID,
				Name: site.Name,
				Type: Site.String(),
				Metadata: map[string]string{
					siteUrl:      site.Url,
					siteAdminUrl: site.AdminUrl,
					siteRepoUrl:  site.RepoUrl,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteFiles(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteFile], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var files []file

		if err := json.Unmarshal(respBody, &files); err != nil {
			return err
		}

		for _, file := range files {
			secretInfo.appendResource(NetlifyResource{
				ID:   site.ID + "/" + file.ID, // combine site id with file id to make it unique
				Name: file.Path,
				Type: SiteFile.String(),
				Metadata: map[string]string{
					fileMimeType: file.MimeType,
				},
				Parent: &site,
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

func captureSiteEnvVar(client *http.Client, key string, site NetlifyResource, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeNetlifyRequest(client, fmt.Sprintf(apiEndpoints[SiteEnvVar], site.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var envVariables []envVariable

		if err := json.Unmarshal(respBody, &envVariables); err != nil {
			return err
		}

		for _, envVar := range envVariables {
			// multiple values exist for each env variable, so we append separate resource for each value
			for _, value := range envVar.Values {
				secretInfo.appendResource(NetlifyResource{
					ID:   envVar.Key + "/" + value.ID,
					Name: envVar.Key + "/***" + value.Value[len(value.Value)-4:], // append last 4 characters of value with key to make it unique
					Type: SiteEnvVar.String(),
					Metadata: map[string]string{
						"value":  value.Value,
						"scopes": strings.Join(envVar.Scopes, ";"),
					},
				})
			}
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
