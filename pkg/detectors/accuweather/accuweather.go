package accuweather

import (
	"context"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

const accuweatherURL = "https://dataservice.accuweather.com"
const requiredShannonEntropy = 4

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"accuweather"}) + `([a-z0-9A-Z\%]{35})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"accuweather"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Accuweather secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		k := match[1]
		if detectors.StringShannonEntropy(k) < requiredShannonEntropy {
			continue
		}
		matches[k] = struct{}{}
	}

	for key := range matches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Accuweather,
			Raw:          []byte(key),
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyAccuweather(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAccuweather(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accuweatherURL+"/locations/v1/cities/autocomplete?apikey="+key+"&q=----&language=en-us", nil)
	if err != nil {
		return false, err
	}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// https://developer.accuweather.com/accuweather-locations-api/apis/get/locations/v1/cities/autocomplete
	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// 403 indicates lack of permission, but valid token
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Accuweather
}

func (s Scanner) Description() string {
	return "AccuWeather is a weather forecasting service. AccuWeather API keys can be used to access weather data and forecasts."
}
