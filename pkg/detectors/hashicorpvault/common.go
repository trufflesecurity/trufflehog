// Package hashicorpvault contains logic shared by the HashiCorp Vault
// detectors (hashicorpvaulttoken, hashicorpvaultbatchtoken) for verifying
// tokens against the /v1/auth/token/lookup-self endpoint.
package hashicorpvault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type LookupResponse struct {
	Data struct {
		DisplayName string   `json:"display_name"`
		EntityId    string   `json:"entity_id"`
		ExpireTime  string   `json:"expire_time"`
		Orphan      bool     `json:"orphan"`
		Policies    []string `json:"policies"`
		Renewable   bool     `json:"renewable"`
		Type        string   `json:"type"`
	}
}

// VerifyVaultToken looks up token against baseUrl's /v1/auth/token/lookup-self
// endpoint. detType is used to scope request deduplication when client was
// created with detectors.NewClientWithDedup; it has no effect otherwise.
func VerifyVaultToken(
	ctx context.Context,
	client *http.Client,
	detType detector_typepb.DetectorType,
	baseUrl string,
	token string,
) (bool, *LookupResponse, error) {
	lookupUrl, err := url.JoinPath(baseUrl, "/v1/auth/token/lookup-self")
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		lookupUrl,
		http.NoBody,
	)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("X-Vault-Token", token)

	res, err := detectors.DoWithDedup(client, detType, fmt.Sprintf("%s:%s", baseUrl, token), req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var resp LookupResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return false, nil, err
		}

		return true, &resp, nil

	case http.StatusForbidden, http.StatusUnauthorized:
		return false, nil, nil

	default:
		return false, nil, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}
