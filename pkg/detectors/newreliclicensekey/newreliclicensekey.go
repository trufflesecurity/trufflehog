package newreliclicensekey

import (
	"context"
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
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/#license-key
	// US region keys are 40 characters hexadecimal strings ending with "FFFFNRAL"
	// EU region keys have the same format but first 6 characters are "eu01xx"
	keyPat = regexp.MustCompile(`\b([0-9a-x]{6}[0-9a-f]{26}FFFFNRAL)\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"ffffnral"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicLicenseKey
}

func (s Scanner) Description() string {
	return "New Relic license keys are unique authentication tokens used to send telemetry data (metrics, logs, and traces) from your applications and infrastructure to New Relic."
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

// verify checks if the provided key is valid by making a request to the New Relic Metrics API.
// It sends a POST request to the metrics endpoint. A valid key will result in a 202 Accepted response, while an invalid key will return a 403 Forbidden.
// Even though the response is 202, no data is actually published to New Relic since the request body is empty.
// https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/report-metrics-metric-api/
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	host := "https://metric-api.newrelic.com"
	region := "us"
	if strings.HasPrefix(key, "eu01xx") {
		// EU region keys have a different host
		host = "https://metric-api.eu.newrelic.com"
		region = "eu"
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, host+"/metric/v1", http.NoBody)
	if err != nil {
		return false, nil, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Api-Key", key)

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
	case http.StatusAccepted:
		return true, map[string]string{"region": region}, nil
	case http.StatusForbidden:
		return false, map[string]string{"region": region}, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
