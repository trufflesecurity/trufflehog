package sanity

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
	authTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sanity"}) + `\b(sk[A-Za-z0-9]{79})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sanity"}
}

func (s Scanner) Description() string {
	return "Sanity is the modern CMS that transforms content into a competitive advantage. Customize, collaborate, and scale your digital experiences seamlessly."
}

// FromData will find and optionally verify Meraki API Key secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// uniqueMatches will hold unique match values and ensure we only process unique matches found in the data string
	var uniqueMatches = make(map[string]struct{})

	for _, match := range authTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Sanity,
			Raw:          []byte(match),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, verificationErr := verifySanityAuthToken(ctx, s.client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Sanity
}

/*
verifySanityAuthToken verifies if the passed matched auth token for sanity is active or not.
auth docs: https://www.sanity.io/docs/http-auth
api docs: https://www.sanity.io/docs/reference/http/access#tag/permissions/GET/vX/access/permissions/me
*/
func verifySanityAuthToken(ctx context.Context, client *http.Client, authToken string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sanity.io/vX/access/permissions/me", http.NoBody)
	if err != nil {
		return false, err
	}

	// set the required auth header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))

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
