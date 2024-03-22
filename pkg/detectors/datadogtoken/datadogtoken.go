package datadogtoken

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) DefaultEndpoint() string { return "https://api.datadoghq.com" }

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	appPat = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{40})\b`)
	apiPat = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"datadog"}
}

// FromData will find and optionally verify DatadogToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	appMatches := appPat.FindAllStringSubmatch(dataStr, -1)
	apiMatches := apiPat.FindAllStringSubmatch(dataStr, -1)

	for _, apiMatch := range apiMatches {
		if len(apiMatch) != 2 {
			continue
		}
		resApiMatch := strings.TrimSpace(apiMatch[1])
		appIncluded := false
		for _, appMatch := range appMatches {
			if len(appMatch) != 2 {
				continue
			}
			resAppMatch := strings.TrimSpace(appMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resAppMatch),
				RawV2:        []byte(resAppMatch + resApiMatch),
				ExtraData: map[string]string{
					"Type": "Application+APIKey",
				},
			}

			if verify {
				for _, baseURL := range s.Endpoints(s.DefaultEndpoint()) {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v2/users", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					req.Header.Add("DD-APPLICATION-KEY", resAppMatch)
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resApiMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}
			}
			appIncluded = true
			results = append(results, s1)
		}

		if !appIncluded {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resApiMatch),
				RawV2:        []byte(resApiMatch),
				ExtraData: map[string]string{
					"Type": "APIKeyOnly",
				},
			}

			if verify {

				for _, baseURL := range s.Endpoints(s.DefaultEndpoint()) {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v1/validate", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resApiMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatadogToken
}
