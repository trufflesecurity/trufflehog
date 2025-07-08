package testingbot

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"testingbot"}) + `\b([0-9a-z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"testingbot"}) + `\b([0-9a-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"testingbot"}
}

// FromData will find and optionally verify TestingBot secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueIDMatches, uniqueKeyMatches := make(map[string]struct{}), make(map[string]struct{})

	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIDMatches[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for id := range uniqueIDMatches {
		for key := range uniqueKeyMatches {
			if id == key {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_TestingBot,
				Raw:          []byte(key),
			}

			if verify {
				isVerified, verificationErr := verifyTestingBot(ctx, client, id, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TestingBot
}

func (s Scanner) Description() string {
	return "TestingBot provides cross-browser testing services. TestingBot credentials can be used to automate tests on various browsers and devices."
}

func verifyTestingBot(ctx context.Context, client *http.Client, id, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.testingbot.com/v1/user", nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(id, secret)
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
