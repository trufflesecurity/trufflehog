package api_token

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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"make"}) + `\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"make", "token", "api"}
}

// FromData will find and optionally verify Make secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MakeApiToken,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	baseURLs := []string{
		"https://eu1.make.com/api/v2/",
		"https://eu2.make.com/api/v2/",
		"https://us1.make.com/api/v2/",
		"https://us2.make.com/api/v2/",
		"https://us1.make.celonis.com/api/v2/",
		"https://eu1.make.celonis.com/api/v2/",
	}

	var lastErr error
	for _, baseURL := range baseURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"users/me/current-authorization", nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Authorization", "Token "+token)

		res, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		func() {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}()

		switch res.StatusCode {
		case http.StatusOK:
			return true, nil, nil
		case http.StatusUnauthorized:
			// Determinate failure - invalid token
			continue
		default:
			// Indeterminate failure - unexpected response
			lastErr = fmt.Errorf("unexpected status code: %d", res.StatusCode)
			continue
		}
	}

	// If we got here, either all endpoints failed or we had errors
	if lastErr != nil {
		return false, nil, lastErr
	}
	return false, nil, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MakeApiToken
}

func (s Scanner) Description() string {
	return "Make.com is a low-code/no-code automation platform that allows users to connect apps and services typically to automate business workflows. This detector identifies API tokens used for Make.com integrations."
}
