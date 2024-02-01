package github_oauth2

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/github"
)

type Scanner struct{ detectors.EndpointSetter }

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Oauth2 client ID and secret
	oauth2ClientIDPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([a-f0-9]{20})\b`)
	oauth2ClientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([a-f0-9]{40})\b`)
)

const (
	githubBadVerificationCodeError = "bad_verification_code"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"github"}
}

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Oauth2 client ID and secret
	oauth2ClientIDMatches := oauth2ClientIDPat.FindAllStringSubmatch(dataStr, -1)
	oauth2ClientSecretMatches := oauth2ClientSecretPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range oauth2ClientIDMatches {
		if len(idMatch) != 2 {
			continue
		}
		for _, secretMatch := range oauth2ClientSecretMatches {
			if len(secretMatch) != 2 {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GitHubOauth2,
				Raw:          []byte(idMatch[1]),
				RawV2:        []byte(idMatch[1] + secretMatch[1]),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
			}

			config := &clientcredentials.Config{
				ClientID:     idMatch[1],
				ClientSecret: secretMatch[1],
				TokenURL:     github.Endpoint.TokenURL,
			}
			_, err := config.Token(ctx)
			if err != nil && strings.Contains(err.Error(), githubBadVerificationCodeError) {
				s1.Verified = true
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GitHubOauth2
}
