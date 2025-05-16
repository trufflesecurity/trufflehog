package mux

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const muxAPIBaseURL = "https://api.mux.com"

func makeAPIRequest(client *http.Client, key, secret, method, endpoint string) ([]byte, int, error) {
	req, err := http.NewRequest(method, muxAPIBaseURL+"/"+endpoint, nil)
	if err != nil {
		return nil, 0, err
	}

	req.SetBasicAuth(key, secret)
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	return body, res.StatusCode, nil
}

func testAllPermissions(client *http.Client, info *secretInfo, key string, secret string) error {
	testsConfig, err := readTestsConfig()
	if err != nil {
		return err
	}

	for _, test := range testsConfig.Tests {
		hasPermission, err := test.testPermission(client, key, secret)
		if err != nil {
			return err
		}
		if !hasPermission {
			continue
		}
		info.addPermission(test.ResourceType, test.Permission)
	}

	return nil
}

func populateAllResources(client *http.Client, info *secretInfo, key string, secret string) error {
	if info.hasPermission(ResourceTypeVideo, Read) {
		if err := populateAssets(client, info, key, secret); err != nil {
			return err
		}
	}
	if info.hasPermission(ResourceTypeData, Read) {
		if err := populateAnnotations(client, info, key, secret); err != nil {
			return err
		}
	}
	if info.hasPermission(ResourceTypeSystem, Read) {
		if err := populateSigningKeys(client, info, key, secret); err != nil {
			return err
		}
	}
	return nil
}

func populateAssets(client *http.Client, info *secretInfo, key string, secret string) error {
	const limit = 100

	for page := 1; ; page++ {
		url := fmt.Sprintf("/video/v1/assets?limit=%d&page=%d&timeframe[]=100:days", limit, page)
		body, statusCode, err := makeAPIRequest(client, key, secret, http.MethodGet, url)
		if err != nil {
			return err
		}
		if statusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", statusCode)
		}

		resp := assetListResponse{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		if len(resp.Data) == 0 {
			break
		}
		info.Assets = append(info.Assets, resp.Data...)
	}
	return nil
}

func populateAnnotations(client *http.Client, info *secretInfo, key string, secret string) error {
	const limit = 100

	for page := 1; ; page++ {
		url := fmt.Sprintf("/data/v1/annotations?limit=%d&page=%d&timeframe[]=100:days", limit, page)
		body, statusCode, err := makeAPIRequest(client, key, secret, http.MethodGet, url)
		if err != nil {
			return err
		}
		if statusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", statusCode)
		}

		resp := annotationListResponse{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		if len(resp.Data) == 0 {
			break
		}
		info.Annotations = append(info.Annotations, resp.Data...)
	}
	return nil
}

func populateSigningKeys(client *http.Client, info *secretInfo, key string, secret string) error {
	const limit = 100

	for page := 1; ; page++ {
		url := fmt.Sprintf("/system/v1/signing-keys?limit=%d&page=%d&timeframe[]=100:days", limit, page)
		body, statusCode, err := makeAPIRequest(client, key, secret, http.MethodGet, url)
		if err != nil {
			return err
		}
		if statusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", statusCode)
		}

		resp := signingKeyListResponse{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		if len(resp.Data) == 0 {
			break
		}
		info.SigningKeys = append(info.SigningKeys, resp.Data...)
	}
	return nil
}
