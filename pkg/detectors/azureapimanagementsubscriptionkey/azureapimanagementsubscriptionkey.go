package azureapimanagementsubscriptionkey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	urlPat        = regexp.MustCompile(`https://([a-z0-9][a-z0-9-]{0,48}[a-z0-9])\.azure-api\.net`)                                              // https://azure.github.io/PSRule.Rules.Azure/en/rules/Azure.APIM.Name/
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", ".azure-api.net", "subscription", "key"}) + `([a-zA-Z-0-9]{32})`) // pattern for both Primary and secondary key

	invalidHosts  = simple.NewCache[struct{}]()
	noSuchHostErr = errors.New("no such host")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".azure-api.net"}
}

// FromData will find and optionally verify Azure Subscription keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("azureapimanagementsubscriptionkey")
	dataStr := string(data)

	urlMatchesUnique := make(map[string]struct{})
	for _, urlMatch := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		urlMatchesUnique[urlMatch[0]] = struct{}{}
	}
	keyMatchesUnique := make(map[string]struct{})
	for _, keyMatch := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatchesUnique[strings.TrimSpace(keyMatch[1])] = struct{}{}
	}

EndpointLoop:
	for baseUrl := range urlMatchesUnique {
		for key := range keyMatchesUnique {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureAPIManagementSubscriptionKey,
				Raw:          []byte(baseUrl),
				RawV2:        []byte(baseUrl + ":" + key),
			}

			if verify {
				if invalidHosts.Exists(baseUrl) {
					logger.V(3).Info("Skipping invalid registry", "baseUrl", baseUrl)
					continue EndpointLoop
				}

				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := s.verifyMatch(ctx, client, baseUrl, key)
				s1.Verified = isVerified
				if verificationErr != nil {
					if errors.Is(verificationErr, noSuchHostErr) {
						invalidHosts.Set(baseUrl, struct{}{})
						continue EndpointLoop
					}
					s1.SetVerificationError(verificationErr, baseUrl)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureAPIManagementSubscriptionKey
}

func (s Scanner) Description() string {
	return "Azure API Management provides a direct management REST API for performing operations on selected entities, such as users, groups, products, and subscriptions."
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, baseUrl, key string) (bool, error) {
	url := baseUrl + "/echo/resource" // default testing endpoint for api management services
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Ocp-Apim-Subscription-Key", key)
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
