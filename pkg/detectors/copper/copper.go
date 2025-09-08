package copper

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	emailPat = regexp.MustCompile(common.EmailPattern)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"copper"}) + `\b([a-f0-9]{32})\b`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Copper
}

func (s Scanner) Description() string {
	return "Copper is a CRM platform that helps businesses manage their relationships with customers and leads. Copper API keys can be used to access and modify customer data and interactions."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"copper"}
}

// FromData will find and optionally verify Copper secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var emails, apiKeys = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		emails[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		apiKeys[match[1]] = struct{}{}
	}

	for email := range emails {
		for apiKey := range apiKeys {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Copper,
				Raw:          []byte(apiKey),
				RawV2:        []byte(apiKey + email),
			}

			if verify {
				isVerified, verificationErr := verifyCopper(ctx, client, email, apiKey)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, apiKey)
			}

			results = append(results, s1)

		}

	}

	return results, nil
}

func verifyCopper(ctx context.Context, client *http.Client, emailID, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.copper.com/developer_api/v1/account", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-PW-AccessToken", apiKey)
	req.Header.Add("X-PW-Application", "developer_api")
	req.Header.Add("X-PW-UserEmail", emailID)
	req.Header.Add("Content-Type", "application/json")

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
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
