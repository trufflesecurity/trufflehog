package dwolla

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"dwolla"}) + `\b([a-zA-Z-0-9]{50})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dwolla"}) + `\b([a-zA-Z-0-9]{50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dwolla"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Dwolla secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIDs := make(map[string]struct{})
	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIDs[matches[1]] = struct{}{}
	}

	uniqueSecrets := make(map[string]struct{})
	for _, matches := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[matches[1]] = struct{}{}
	}

	for id := range uniqueIDs {
		for secret := range uniqueSecrets {
			if id == secret {
				continue // Skip if ID and secret are the same.
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dwolla,
				Raw:          []byte(id),
				RawV2:        []byte(id + secret),
			}

			if verify {
				client := s.getClient()
				isVerified, err := verifyMatch(ctx, client, id, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(err, id, secret)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, id, secret string) (bool, error) {
	data := fmt.Sprintf("%s:%s", id, secret)
	encoded := b64.StdEncoding.EncodeToString([]byte(data))
	payload := strings.NewReader("grant_type=client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api-sandbox.dwolla.com/token", payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))

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
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dwolla
}

func (s Scanner) Description() string {
	return "Dwolla is a payment services provider that allows businesses to send, receive, and facilitate payments. Dwolla API keys can be used to access and manage these payment services."
}
