package dovico

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"dovico"}) + `\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dovico"}) + `\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dovico"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Dovico secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	uniqueUserKeys := make(map[string]struct{})
	for _, matches := range userPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueUserKeys[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for userKey := range uniqueUserKeys {
			if key == userKey {
				continue // Skip if ID and secret are the same.
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dovico,
				Raw:          []byte(key),
				RawV2:        []byte(fmt.Sprintf("%s:%s", key, userKey)),
			}

			if verify {
				client := s.getClient()
				isVerified, err := verifyMatch(ctx, client, key, userKey)
				s1.Verified = isVerified
				s1.SetVerificationError(err, key, userKey)
			}

			results = append(results, s1)

			// Credentials have 1:1 mapping so we can stop checking other user keys once it is verified
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, key, user string) (bool, error) {
	// Reference: https://timesheet.dovico.com/developer/API_doc/#t=API_Overview.html
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.dovico.com/employees/?version=7", http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf(`WRAP access_token="client=%s&user_token=%s"`, key, user))
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
	return detectorspb.DetectorType_Dovico
}

func (s Scanner) Description() string {
	return "Dovico is a time tracking and project management service. Dovico keys can be used to access and manage time tracking and project data."
}
