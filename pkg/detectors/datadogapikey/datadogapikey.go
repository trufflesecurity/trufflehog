package datadogapikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	client *http.Client
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
	apiKeyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{32})\b`)
	datadogURLPat = regexp.MustCompile(`\b(api(?:\.[a-z0-9-]+)?\.(?:datadoghq|ddog-gov)\.[a-z]{2,3})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"datadog", "ddog-gov"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return client
}

// FromData will find and optionally verify DatadogToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiMatches := apiKeyPat.FindAllStringSubmatch(dataStr, -1)
	var uniqueFoundUrls = make(map[string]struct{})
	for _, matches := range datadogURLPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueFoundUrls[matches[1]] = struct{}{}
	}
	endpoints := make([]string, 0, len(uniqueFoundUrls))
	for endpoint := range uniqueFoundUrls {
		endpoints = append(endpoints, "https://"+endpoint)
	}

	for _, apiMatch := range apiMatches {
		resApiMatch := strings.TrimSpace(apiMatch[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DatadogApikey,
			Raw:          []byte(resApiMatch),
		}

		if verify {
			for _, baseURL := range s.Endpoints(endpoints...) {
				client := s.getClient()
				isVerified, verificationErr := verifyMatch(ctx, client, resApiMatch, baseURL)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resApiMatch)
				if isVerified {
					s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch, "endpoint": baseURL}
					// break the loop once we've successfully validated the token against a baseURL
					break
				}
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey, baseUrl string) (bool, error) {
	// Reference: https://docs.datadoghq.com/api/latest/authentication/

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseUrl+"/api/v1/validate", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("DD-API-KEY", apiKey)
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
	case http.StatusForbidden:
		return false, nil
	case http.StatusTooManyRequests:
		return false, fmt.Errorf("too many requests")
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatadogApikey
}

func (s Scanner) Description() string {
	return "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."
}
