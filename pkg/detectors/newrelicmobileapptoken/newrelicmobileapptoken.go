package newrelicmobileapptoken

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
	// US region keys start with AA, followed by a 40 characters hexadecimal string, end with "-NRMA"
	// EU region keys start with eu01xx, followed by a 36 characters hexadecimal string, end with "-NRMA"
	keyPat = regexp.MustCompile(`\b((AA[0-9a-f]{40}|eu01xx[0-9a-f]{36})-NRMA)\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"-nrma"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NewRelicMobileAppToken
}

func (s Scanner) Description() string {
	return "A New Relic Mobile App Token is an authentication key used to send mobile application telemetry data (such as performance metrics, crashes, and events) from iOS and Android apps to New Relic for monitoring and analysis. It is specific to each mobile app and ensures secure data ingestion."
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

// verify checks if the provided key is valid by making a request to the New Relic Android Agent internal API.
// A POST request is made to the /mobile/v5/connect endpoint. If the response status code is 400,
// it indicates that the key is valid but the request is malformed (since we're not sending a proper payload),
// while a 401 status code indicates that the key is invalid. Any other status code is treated as an error.
// This API is not documented, and was discovered by digging into New Relic's Android agent SDK code:
// https://github.com/newrelic/newrelic-android-agent
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	host := "https://mobile-collector.newrelic.com"
	region := "us"
	if strings.HasPrefix(key, "eu01xx") {
		// EU region keys have a different host
		host = "https://mobile-collector.eu01.nr-data.net"
		region = "eu"
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, host+"/mobile/v5/connect", http.NoBody)
	if err != nil {
		return false, nil, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-App-License-Key", key)

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
	case http.StatusBadRequest:
		return true, map[string]string{"region": region}, nil
	case http.StatusUnauthorized:
		return false, map[string]string{"region": region}, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
