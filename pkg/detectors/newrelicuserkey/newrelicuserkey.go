package newrelicuserkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(NRAK-[A-Z0-9]{27})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"nrak-"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicUserKey
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
		}

		if verify {
			isVerified, extraData, verificationErr := s.verify(ctx, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
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
	regionUrls := map[string]string{
		"us": "https://api.newrelic.com/graphql",
		"eu": "https://api.eu.newrelic.com/graphql",
	}
	client := s.getClient()
	body := "{ requestContext { userId } }"
	errs := make([]error, 0, len(regionUrls))
	for region, regionUrl := range regionUrls {
		req, err := http.NewRequestWithContext(
			ctx, http.MethodPost, regionUrl, strings.NewReader(body))
		if err != nil {
			return false, nil, fmt.Errorf("error constructing request: %w", err)
		}
		req.Header.Set("API-Key", key)

		res, err := client.Do(req)
		if err != nil {
			return false, nil, fmt.Errorf("error making request: %w", err)
		}
		defer func() {
			_ = res.Body.Close()
		}()

		switch res.StatusCode {
		case http.StatusOK:
			var resp graphqlResponse
			if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
				errs = append(errs, fmt.Errorf("error decoding response for region %s: %w", region, err))
				continue
			}
			return true, map[string]string{"region": region, "user_id": resp.Data.RequestContext.UserID}, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			// 401 means the key is invalid, 403 means the region is incorrect
			continue
		default:
			errs = append(errs, fmt.Errorf("unexpected status code for region %s: %d", region, res.StatusCode))
		}
	}
	return false, nil, errors.Join(errs...)
}
