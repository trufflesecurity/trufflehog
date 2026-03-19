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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider

	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(NRIQ-[a-zA-Z0-9-_]{25})`)
	accountIDPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"relic", "account", "id"}) + `\b(\d{4,10})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"nriq-"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicInsightsQueryKey
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
			}

			if verify && accountIDResMatch != "" {
				isVerified, extraData, verificationErr := s.verify(ctx, keyResMatch, accountIDResMatch)
				s1.Verified = isVerified
				s1.ExtraData = extraData
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
	regionUrls := map[string]string{
		"us": fmt.Sprintf("https://insights-api.newrelic.com/v1/accounts/%s/query?nrql=SELECT%%201", accountID),
		"eu": fmt.Sprintf("https://insights-api.eu.newrelic.com/v1/accounts/%s/query?nrql=SELECT%%201", accountID),
	}
	errs := make([]error, 0, len(regionUrls))
	for region, regionUrl := range regionUrls {
		verified, err := s.verifyRegion(ctx, key, regionUrl)
		if err != nil {
			errs = append(errs, fmt.Errorf("error verifying region %s: %w", region, err))
			continue
		}
		if verified {
			return true, map[string]string{"region": region}, nil
		}
	}
	return false, nil, errors.Join(errs...)
}

func (s Scanner) verifyRegion(ctx context.Context, key, regionUrl string) (bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, regionUrl, http.NoBody)
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
