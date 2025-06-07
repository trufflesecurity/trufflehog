package databrickstoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	domain = regexp.MustCompile(`\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(cloud\.databricks\.com|gcp\.databricks\.com|azuredatabricks\.net))\b`)
	keyPat = regexp.MustCompile(`\b(dapi[0-9a-f]{32}(-\d)?)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"databricks", "dapi"}
}

// FromData will find and optionally verify Databrickstoken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueDomains, uniqueTokens = make(map[string]struct{}), make(map[string]struct{})
	for _, match := range domain.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatabricksToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + domain),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyDatabricksToken(client, domain, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)

				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"token":  token,
						"domain": domain,
					}
				}
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatabricksToken
}

func (s Scanner) Description() string {
	return "Databricks is a cloud data platform. Databricks tokens can be used to authenticate and interact with Databricks services and APIs."
}

func verifyDatabricksToken(client *http.Client, domain, token string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+domain+"/api/2.0/preview/scim/v2/Me", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
