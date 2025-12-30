package datadogapikey

import (
	"context"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "https://api.datadoghq.com" }

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	apiPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{32})\b`)
	datadogURLPat = regexp.MustCompile(`\b(api(?:\.[a-z0-9-]+)?\.(?:datadoghq|ddog-gov)\.[a-z]{2,3})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"datadog", "ddog-gov"}
}

// FromData will find and optionally verify DatadogToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiMatches := apiPat.FindAllStringSubmatch(dataStr, -1)
	var uniqueFoundUrls = make(map[string]struct{})
	for _, matches := range datadogURLPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueFoundUrls[matches[1]] = struct{}{}
	}
	endpoints := make([]string, 0, len(uniqueFoundUrls))
	for endpoint := range uniqueFoundUrls {
		endpoints = append(endpoints, endpoint)
	}

	for _, apiMatch := range apiMatches {
		resApiMatch := strings.TrimSpace(apiMatch[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DatadogApikey,
			Raw:          []byte(resApiMatch),
			RawV2:        []byte(resApiMatch),
			ExtraData: map[string]string{
				"Type": "APIKeyOnly",
			},
		}

		if verify {
			for _, baseURL := range s.Endpoints(endpoints...) {
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
						s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch, "endpoint": baseURL}
						// break the loop once we've successfully validated the token against a baseURL
						break
					}
				}
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatadogApikey
}

func (s Scanner) Description() string {
	return "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."
}
