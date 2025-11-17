package dotdigital

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

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
	emailPat = regexp.MustCompile(`\b(apiuser-[a-z0-9]{12}@apiconnector.com)\b`)
	passPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"pw", "pass"}) + `\b([a-zA-Z0-9\S]{8,24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"@apiconnector.com"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Dotdigital secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueEmails, uniquePasswords = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmails[matches[1]] = struct{}{}
	}
	for _, matches := range passPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePasswords[matches[1]] = struct{}{}
	}

	for email := range uniqueEmails {
		for password := range uniquePasswords {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dotdigital,
				Raw:          []byte(email),
				RawV2:        []byte(email + password),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyMatch(ctx, client, email, password)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)

			if s1.Verified {
				// Once the email is verified, we can stop checking other passwords for it.
				break
			}
		}
	}
	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, email, pass string) (bool, error) {
	// Reference: https://developer.dotdigital.com/reference/get-account-information

	timeout := 10 * time.Second
	client.Timeout = timeout
	url := "https://r1-api.dotdigital.com/v2/account-info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(email, pass)
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
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dotdigital
}

func (s Scanner) Description() string {
	return "Dotdigital is an email marketing automation platform. API keys can be used to access and manage email campaigns and related data."
}
