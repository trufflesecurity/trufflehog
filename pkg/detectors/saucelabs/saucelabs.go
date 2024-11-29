package saucelabs

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
	// as per signup page username can be between 2 to 70 characters and must only contain letters, numbers, or characters (_-.)
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"saucelabs", "username"}) + `\b([a-zA-Z0-9_\.-]{2,70})\b`)
	keyPat      = regexp.MustCompile(detectors.PrefixRegex([]string{"saucelabs"}) + `\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"saucelabs"}
}

// FromData will find and optionally verify SauceLabs secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueUserNameMatches, uniqueKeyMatches := make(map[string]struct{}), make(map[string]struct{})

	for _, match := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		uniqueUserNameMatches[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for userName := range uniqueUserNameMatches {
		for key := range uniqueKeyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SauceLabs,
				Raw:          []byte(userName),
				RawV2:        []byte(userName + key),
			}

			if verify {
				isVerified, verificationErr := verifySauceLabKey(ctx, client, userName, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SauceLabs
}

func (s Scanner) Description() string {
	return "A service for cross browser testing, API keys can create and access tests from potentially sensitive internal websites"
}

func verifySauceLabKey(ctx context.Context, client *http.Client, userName, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.eu-central-1.saucelabs.com/team-management/v1/teams", nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(userName, key)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}
}
