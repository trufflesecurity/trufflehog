package hashicorpvaulttoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Vault tokens:
	// newer vault tokens are around 90-120 chars and start with hvs. (HashiCorp Vault Service token)
	// legacy tokens are around 18-40 chars and start with s.
	vaultTokenPat = regexp.MustCompile(
		`\b(hvs\.[A-Za-z0-9_-]{90,120}|s\.[A-Za-z0-9_-]{18,40})(?:$|[^A-Za-z0-9_-])`,
	)

	vaultUrlPat = regexp.MustCompile(`(https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?)(?:\/[^\s]*)?`)
)

func (s Scanner) Keywords() []string {
	// We cant use s. as a keyword because it is too broad so that's why we are using "vault".
	return []string{"hvs.", "vault"}
}

func (Scanner) CloudEndpoint() string { return "" }

func (s Scanner) Description() string {
	return "HashiCorp Vault is a secrets management service. Vault tokens (periodic, service, and admin) can be used to access and manage stored secrets and resources."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range vaultTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	var uniqueVaultUrls = make(map[string]struct{})
	for _, match := range vaultUrlPat.FindAllStringSubmatch(dataStr, -1) {
		url := strings.TrimSpace(match[1])
		uniqueVaultUrls[url] = struct{}{}
	}
	endpoints := make([]string, 0, len(uniqueVaultUrls))
	for endpoint := range uniqueVaultUrls {
		endpoints = append(endpoints, endpoint)
	}

	for token := range uniqueTokens {
		emitted := false
		for _, endpoint := range s.Endpoints(endpoints...) {
			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_HashiCorpVaultToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + endpoint),
				Redacted:     token[:8] + "...",
				SecretParts: map[string]string{
					"token": token,
					"url":   endpoint,
				},
			}

			if verify {
				verified, verificationResp, verificationErr := verifyVaultToken(
					ctx,
					s.getClient(),
					endpoint,
					token,
				)
				result.SetVerificationError(verificationErr, token)
				result.Verified = verified
				if verificationResp != nil {
					result.ExtraData = map[string]string{
						"policies":  strings.Join(verificationResp.Data.Policies, ", "),
						"orphan":    fmt.Sprintf("%v", verificationResp.Data.Orphan),
						"renewable": fmt.Sprintf("%v", verificationResp.Data.Renewable),
						"type":      verificationResp.Data.Type,
						"entity_id": verificationResp.Data.EntityId, // can be helpful in revoking the token
					}
				}
			}

			results = append(results, result)
			emitted = true
		}
		if !emitted {
			// No reachable URL in context — emit an unverified token-only
			// result and annotate why we couldn't verify.
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_HashiCorpVaultToken,
				Raw:          []byte(token),
				Redacted:     "multiple tokens found; no reachable Vault URL found in context; tokens reported unverified",
				ExtraData: map[string]string{
					"verification_note": "no reachable Vault URL found in context; tokens reported unverified",
				},
				SecretParts: map[string]string{
					"token": token,
				},
			})
		}
	}

	return
}

type lookupResponse struct {
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

func verifyVaultToken(
	ctx context.Context,
	client *http.Client,
	baseUrl string,
	token string,
) (bool, *lookupResponse, error) {
	url, err := url.JoinPath(baseUrl, "/v1/auth/token/lookup-self")
	if err != nil {
		return false, nil, err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		http.NoBody,
	)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("X-Vault-Token", token)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var resp lookupResponse
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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HashiCorpVaultToken
}
