package newrelicinsightsquerykey

import (
	"context"
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
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter

	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(NRIQ-[a-zA-Z0-9-_]{25})`)
	accountIDPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"relic", "account", "id"}) + `\b(\d{4,10})\b`)
)

// Cloud endpoints here are hosts, not full URLs - the account ID (discovered
// per match, not fixed) is appended to build the actual request URL.
const (
	usHost = "https://insights-api.newrelic.com"
	euHost = "https://insights-api.eu.newrelic.com"
)

func (Scanner) CloudEndpoints() []string { return []string{usHost, euHost} }

// regionForHost labels the well-known US/EU cloud hosts. A user-configured
// or found host has no known region, so it's left blank.
func regionForHost(host string) string {
	switch host {
	case usHost:
		return "us"
	case euHost:
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
func (s Scanner) Keywords() []string { return []string{"nriq-"} }

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicInsightsQueryKey
}

func (s Scanner) Description() string {
	return "A New Relic Insights Query Key is a read-only API key used to execute NRQL queries against your account's event data via the legacy Insights Query API. It allows secure retrieval of analytics data without permitting any data ingestion or modification."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	accountIDMatches := accountIDPat.FindAllStringSubmatch(dataStr, -1)
	uniqueAccountIDMatches := make(map[string]struct{})
	for _, match := range accountIDMatches {
		uniqueAccountIDMatches[match[1]] = struct{}{}
	}

	for _, keyMatch := range keyMatches {
		for accountID := range uniqueAccountIDMatches {
			keyResMatch := strings.TrimSpace(keyMatch[1])
			accountIDResMatch := strings.TrimSpace(accountID)

			s1 := detectors.Result{
				DetectorType: s.Type(),
				Raw:          []byte(keyResMatch),
				RawV2:        []byte(keyResMatch + accountIDResMatch),
				Redacted:     keyResMatch[:8] + "...",
				SecretParts: map[string]string{
					"key":        keyResMatch,
					"account_id": accountIDResMatch,
				},
			}

			if verify {
				isVerified, extraData, verificationErr := s.verify(ctx, keyResMatch, accountIDResMatch)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				if region, ok := extraData["region"]; ok {
					s1.SecretParts["region"] = region
				}
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

// verify checks if the provided key is valid by making a request to the New Relic Insights Query API.
// It checks both the US and EU endpoints before returning an error.
// Account ID is required to verify as the API endpoint is account-specific.
func (s Scanner) verify(ctx context.Context, key string, accountID string) (bool, map[string]string, error) {
	hosts := s.Endpoints(nil)
	errs := make([]error, 0, len(hosts))
	for _, host := range hosts {
		endpoint := fmt.Sprintf("%s/v1/accounts/%s/query?nrql=SELECT%%201", host, accountID)
		verified, err := s.verifyEndpoint(ctx, key, endpoint)
		if err != nil {
			errs = append(errs, fmt.Errorf("error verifying host %s: %w", host, err))
			continue
		}
		if verified {
			extraData := map[string]string{}
			if region := regionForHost(host); region != "" {
				extraData["region"] = region
			}
			return true, extraData, nil
		}
	}
	return false, nil, errors.Join(errs...)
}

func (s Scanner) verifyEndpoint(ctx context.Context, key, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Set("X-Query-Key", key)

	client := s.getClient()
	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
