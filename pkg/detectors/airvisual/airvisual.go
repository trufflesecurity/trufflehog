package airvisual

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"airvisual"}) + `\b([a-z0-9-]{36})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airvisual"}
}

// FromData will find and optionally verify AirVisual secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AirVisual,
			Raw:          []byte(key),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyAirVisualKey(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAirVisualKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.airvisual.com/v2/countries?key=%s", key), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/vnd.airvisual+json; version=3")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirVisual
}

func (s Scanner) Description() string {
	return "AirVisual provides air quality information and monitoring. The API key allows access to various air quality data and services."
}
