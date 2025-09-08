package currentsapi

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"currentsapi"}) + `([a-zA-Z0-9_-]{48})`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CurrentsAPI
}

func (s Scanner) Description() string {
	return "CurrentsAPI provides access to the latest news and trends. CurrentsAPI keys can be used to authenticate requests and retrieve news data."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"currentsapi"}
}

// FromData will find and optionally verify CurrentsAPI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens = make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CurrentsAPI,
			Raw:          []byte(token),
		}

		if verify {
			isVerified, verificationErr := verifyCurrentsAPI(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyCurrentsAPI(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.currentsapi.services/v1/latest-news", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", token)

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
