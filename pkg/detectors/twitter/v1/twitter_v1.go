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
	detectors.DefaultMultiPartCredentialProvider

	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twitter"}) + `\b([A-Z]{22}%[a-zA-Z-0-9]{23}%[a-zA-Z-0-9]{6}%[a-zA-Z-0-9]{3}%[a-zA-Z-0-9]{9}%[a-zA-Z-0-9]{52})\b`)
)

func (s Scanner) Version() int { return 1 }

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twitter"}
}

// FromData will find and optionally verify Twitter secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}

	for resMatch := range keyMatches {
		resMatch = strings.TrimSpace(resMatch)

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Twitter,
			Raw:          []byte(resMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, err := s.VerifyTwitterToken(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(err)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twitter
}

func (s Scanner) Description() string {
	return "Twitter API keys can be used to interact with the Twitter API to post tweets, read timelines, and access other Twitter functionalities."
}

func (s Scanner) VerifyTwitterToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/tweets/20", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}
