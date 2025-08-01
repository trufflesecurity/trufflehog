package rootly

import (
	"context"
	"net/http"

	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(rootly_[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rootly_"}
}

// FromData will find and optionally verify Rootly secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Rootly,
			Raw:          []byte(match),
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {

	// this endpoint returns 200 if results exist and 404 if incidents do not exist or that token is not authorized
	// considering both 200 and 404 as positive results i.e. the token is valid
	// /user/me endpoint does not verify Team and Global API Keys returning 422 error. (There are 3 types of API keys in Rootly, Global, Team and Personal)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.rootly.com/v1/incidents", http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := client.Do(req)

	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK, http.StatusNotFound:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Rootly
}

func (s Scanner) Description() string {
	return "Rootly is an incident management platform. Rootly API keys can be used to access and manage incident data and other services."
}
