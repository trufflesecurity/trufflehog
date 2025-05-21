package zipapi

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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([A-Z0-9a-z]{32})\b`)
	emailPat = regexp.MustCompile(common.EmailPattern)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([a-zA-Z0-9!=@#$%^]{7,})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zipapi"}
}

// FromData will find and optionally verify Zipapi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueEmailMatches, uniqueKeyMatches, uniquePassMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range pwordPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePassMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for keyMatch := range uniqueKeyMatches {
		for emailMatch := range uniqueEmailMatches {
			for passMatch := range uniquePassMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZipAPI,
					Raw:          []byte(keyMatch),
				}

				if verify {
					isVerified, verificationErr := verifyZipAPI(ctx, client, emailMatch, keyMatch, passMatch)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, keyMatch)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZipAPI
}

func (s Scanner) Description() string {
	return "ZipAPI is a service used to retrieve ZIP code information. ZipAPI keys can be used to access and retrieve this information from their API."
}

func verifyZipAPI(ctx context.Context, client *http.Client, email, key, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://service.zipapi.us/zipcode/90210/?X-API-KEY=%s", key), http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(email, password)

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
