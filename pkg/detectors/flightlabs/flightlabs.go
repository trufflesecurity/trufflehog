package flightlabs

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(`\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{86})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"}
}

func (s Scanner) getClient() *http.Client {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	return client
}

// FromData will find and optionally verify FlightLabs secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[match[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FlightLabs,
			Raw:          []byte(key),
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, s.getClient(), key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, secret string) (bool, error) {
	// API Reference: https://www.goflightlabs.com/airports-by-filters

	url := fmt.Sprintf("https://www.goflightlabs.com/airports-by-filter?access_key=%s&iata_code=JFK", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FlightLabs
}

func (s Scanner) Description() string {
	return "FlightLabs provides a comprehensive API for accessing real-time and historical flight data. The API keys can be used to query flight information, schedules, and other related data."
}
