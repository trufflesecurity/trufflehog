package zipbooks

import (
	"context"
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	emailPat = regexp.MustCompile(common.EmailPattern)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zipbooks", "password"}) + `\b([a-zA-Z0-9!=@#$%^]{8,})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zipbooks"}
}

// FromData will find and optionally verify Zipbooks secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	pwordMatches := pwordPat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for emailMatch := range uniqueEmailMatches {
		for _, pwordMatch := range pwordMatches {
			resPword := strings.TrimSpace(pwordMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ZipBooks,
				Raw:          []byte(emailMatch),
			}

			if verify {
				isVerified, verificationErr := verifyZipBooksCredentials(ctx, client, emailMatch, resPword)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, emailMatch)
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZipBooks
}

func (s Scanner) Description() string {
	return "ZipBooks is an accounting software service that allows businesses to manage their finances online. The credentials can be used to access and manage financial data."
}

func verifyZipBooksCredentials(ctx context.Context, client *http.Client, email, password string) (bool, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"email": "%s", "password": "%s"}`, email, password))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.zipbooks.com/v2/auth/login", payload)
	if err != nil {
		return false, err
	}

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
	case http.StatusUnauthorized, http.StatusNotFound: // username or password not found
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
