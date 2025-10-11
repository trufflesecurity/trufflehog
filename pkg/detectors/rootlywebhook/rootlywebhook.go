package rootlywebhook

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Rootly webhook tokens are 64 character hex strings
	keyPat = regexp.MustCompile(`\b([a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"webhooks.rootly.com"}
}

// FromData will find and optionally verify RootlyWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueMatches := make(map[string]struct{})

	// Look for potential webhook tokens
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_RootlyWebhook,
			Raw:          []byte(match),
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// We don't want to actually create alerts in Rootly. To verify tokens without spamming them,
	// we send a payload that typically causes a 500 error (parsing issue) but still validates the auth.
	// The expected scenario is 500 which means the key is working but the payload format causes an error.
	// In case 200 comes, it means an actual alert has been created in Rootly (hopefully this never happens).
	payload := bytes.NewReader([]byte(`{"rootly":["TruffleHog"]}`))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://webhooks.rootly.com/webhooks/incoming/generic_webhooks", payload)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200: Successfully processed the webhook - this means an actual alert was created in Rootly.
		// Hopefully this never happens, but we at least know the token is verified.
		return true, nil
	case http.StatusInternalServerError:
		// 500: Auth is valid but there was a server error (e.g., parsing issue with our test payload)
		// This is the expected response that indicates the token is valid without creating alerts.
		return true, nil
	case http.StatusNotFound:
		// 404: Integration/webhook not found - token is invalid
		return false, nil
	case http.StatusUnauthorized:
		// 401: Unauthorized - token is invalid
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RootlyWebhook
}

func (s Scanner) Description() string {
	return "Rootly webhook tokens are used to create alerts using incoming webhook requests to its incident management platform."
}
