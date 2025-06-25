package storyblok

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"storyblok"}) + `\b([0-9A-Za-z]{22}tt)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"storyblok"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_StoryblokAccessToken
}

func (s Scanner) Description() string {
	return "Storyblok is a headless CMS that allows developers to build flexible and powerful content management solutions. Storyblok tokens can be used to access and modify content within a Storyblok space."
}

// FromData will find and optionally verify Storyblok secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueAccessTokens = make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccessTokens[match[1]] = struct{}{}
	}

	for accessToken := range uniqueAccessTokens {

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_StoryblokAccessToken,
			Raw:          []byte(accessToken),
		}

		if verify {
			isVerified, verificationErr := verifyStoryBlokAccessToken(ctx, client, accessToken)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

// docs: https://www.storyblok.com/docs/api/content-delivery/v2/getting-started/authentication
func verifyStoryBlokAccessToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.storyblok.com/v1/cdn/spaces/me/?token="+token, nil)
	if err != nil {
		return false, err
	}

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
