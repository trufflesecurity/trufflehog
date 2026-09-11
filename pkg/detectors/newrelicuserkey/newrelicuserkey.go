package newrelicuserkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(NRAK-[A-Z0-9]{27})\b`)
)

const (
	usEndpoint = "https://api.newrelic.com/graphql"
	euEndpoint = "https://api.eu.newrelic.com/graphql"
)

func (Scanner) CloudEndpoints() []string { return []string{usEndpoint, euEndpoint} }

// regionForEndpoint labels the well-known US/EU cloud endpoints. A
// user-configured or found endpoint has no known region, so it's left blank.
func regionForEndpoint(endpoint string) string {
	switch endpoint {
	case usEndpoint:
		return "us"
	case euEndpoint:
		return "eu"
	default:
		return ""
	}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"nrak-"} }

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicUserKey
}

func (s Scanner) Description() string {
	return "A New Relic User API Key is an authentication token used to query data from New Relic via the NerdGraph API or REST API, allowing users to access account data and perform read operations securely. It is primarily used for interacting with New Relic’s query and configuration services."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(resMatch),
			Redacted:     resMatch[:8] + "...",
			SecretParts: map[string]string{
				"key": resMatch,
			},
		}

		if verify {
			isVerified, extraData, verificationErr := s.verify(ctx, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			if region, ok := extraData["region"]; ok {
				s1.SecretParts["region"] = region
			}
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

type graphqlResponse struct {
	Data struct {
		RequestContext struct {
			UserID string `json:"userId"`
		} `json:"requestContext"`
	} `json:"data"`
}

// verify checks if the provided key is valid by making a request to the New Relic NerdGraph API.
// It sends a POST request to the NerdGraph API. A valid key will result in a 200 OK response.
// Invalid key will return in 401 Unauthorized, and a key with incorrect region will return a 403 Forbidden.
// https://docs.newrelic.com/docs/apis/nerdgraph/get-started/introduction-new-relic-nerdgraph/
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	endpoints := s.Endpoints(nil)
	errs := make([]error, 0, len(endpoints))
	for _, endpoint := range endpoints {
		verified, extraData, err := s.verifyEndpoint(ctx, key, endpoint)
		if err != nil {
			errs = append(errs, fmt.Errorf("error verifying endpoint %s: %w", endpoint, err))
			continue
		}
		if verified {
			return true, extraData, nil
		}
	}
	return false, nil, errors.Join(errs...)
}

func (s Scanner) verifyEndpoint(ctx context.Context, key, endpoint string) (bool, map[string]string, error) {
	body := `{"query": "{ requestContext { userId } }"}`
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return false, nil, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", key)

	client := s.getClient()
	res, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var resp graphqlResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return false, nil, fmt.Errorf("error decoding response for endpoint %s: %w", endpoint, err)
		}
		extraData := map[string]string{"user_id": resp.Data.RequestContext.UserID}
		if region := regionForEndpoint(endpoint); region != "" {
			extraData["region"] = region
		}
		return true, extraData, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// 401 means the key is invalid, 403 means the endpoint/region is incorrect
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code for endpoint %s: %d", endpoint, res.StatusCode)
	}
}
