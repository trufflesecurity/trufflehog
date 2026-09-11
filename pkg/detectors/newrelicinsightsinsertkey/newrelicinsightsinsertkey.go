package newrelicinsightsinsertkey

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
	keyPat        = regexp.MustCompile(`\b(NRII-[a-zA-Z0-9-_]{25})`)
)

const (
	usEndpoint = "https://insights-collector.newrelic.com/v1/accounts/`nowaythiscanexist/events"
	euEndpoint = "https://insights-collector.eu01.nr-data.net/v1/accounts/`nowaythiscanexist/events"
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
func (s Scanner) Keywords() []string { return []string{"nrii-"} }

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicInsightsInsertKey
}

func (s Scanner) Description() string {
	return "A New Relic Insights Insert Key is an authentication token used to send event data (such as custom events, logs, and metrics) to New Relic Insights for analysis and visualization. It ensures secure data ingestion from your applications and services."
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
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verify checks if the provided key is valid by making a request to the New Relic Insights API.
// It sends a POST request to the events endpoint. A valid key will result in a 200 OK response, while an invalid key will return a 403 Forbidden.
// Even though the response is 200, no data is actually published to New Relic since the request body is empty.
// https://docs.newrelic.com/docs/data-apis/ingest-apis/event-api/introduction-event-api/
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	endpoints := s.Endpoints(nil)
	errs := make([]error, 0, len(endpoints))
	for _, endpoint := range endpoints {
		verified, err := s.verifyEndpoint(ctx, key, endpoint)
		if err != nil {
			errs = append(errs, fmt.Errorf("error verifying endpoint %s: %w", endpoint, err))
			continue
		}
		if verified {
			extraData := map[string]string{}
			if region := regionForEndpoint(endpoint); region != "" {
				extraData["region"] = region
			}
			return true, extraData, nil
		}
	}
	return false, nil, errors.Join(errs...)
}

func (s Scanner) verifyEndpoint(ctx context.Context, key, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Set("X-Insert-Key", key)

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
	case http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
