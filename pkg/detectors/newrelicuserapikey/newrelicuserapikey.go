package newrelicuserapikey

import (
	"context"
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// New Relic User API Keys start with NRAK- followed by 20-50 alphanumeric characters
	keyPat = regexp.MustCompile(`\b(NRAK-[A-Z0-9]{20,50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"nrak"}
}

// FromData will find and optionally verify NewRelicUserApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NewRelicUserApiKey,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Try US region first
	verified, extraData, err := verifyRegion(ctx, client, token, "https://api.newrelic.com/graphql")
	if verified || err != nil {
		return verified, extraData, err
	}

	// Try EU region if US fails
	return verifyRegion(ctx, client, token, "https://api.eu.newrelic.com/graphql")
}

func verifyRegion(ctx context.Context, client *http.Client, token string, endpoint string) (bool, map[string]string, error) {
	// Use New Relic GraphQL API to verify the key
	// Query the current user to validate the API key
	payload := `{"query":"{ actor { user { email name id } } }"}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", token)

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
		// Valid key
		region := "US"
		if endpoint == "https://api.eu.newrelic.com/graphql" {
			region = "EU"
		}
		return true, map[string]string{
			"region":         region,
			"rotation_guide": "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalid key
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicUserApiKey
}

func (s Scanner) Description() string {
	return "New Relic User API Keys (NRAK-) are used to access New Relic's NerdGraph GraphQL API. These keys grant access to query and manage New Relic data and configurations."
}
