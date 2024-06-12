package twitter

import (
	"context"
	"fmt"
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
	bearerTokenPat = regexp.MustCompile(`\b([a-zA-Z0-9]{20,59}%([a-zA-Z0-9]{3,26}%){0,4}[a-zA-Z0-9]{52})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twitter"}
}

// FromData will find and optionally verify Twitter bearer token in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := make(map[string]struct{})
	for _, match := range bearerTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tokenMatches[match[1]] = struct{}{}
	}

	for match := range tokenMatches {
		resMatch := strings.TrimSpace(match)

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Twitter,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, err := verifyBearerToken(ctx, client, resMatch)
			s1.Verified = isVerified
			if err != nil {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twitter
}

func verifyBearerToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/tweets/20", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		switch res.StatusCode {
		case http.StatusOK, http.StatusForbidden:
			// 403 indicates lack of permission, but valid token (could be due to twitter free tier)
			return true, nil
		case http.StatusUnauthorized:
			return false, nil
		default:
			return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
	}

	return false, err
}
