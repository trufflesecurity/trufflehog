package github_oauth2

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// This detector emits the cartesian product of every client ID and client secret in a
// chunk, so chunks routinely carry dozens of candidate pairs. Implementing ResultVerifier
// lets the verification cache verify only the pairs it has not seen before instead of
// re-verifying the whole product whenever one pair is novel.
var _ detectors.ResultVerifier = (*Scanner)(nil)

var (
	// Oauth2 client ID and secret
	oauth2ClientIDPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([a-zA-Z0-9]{20})\b`)
	oauth2ClientSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"github"}) + `\b([a-f0-9]{40})\b`)

	// tokenURL is a variable rather than a direct reference to github.Endpoint.TokenURL so
	// that verification tests can redirect it at an httptest server.
	tokenURL = github.Endpoint.TokenURL
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
		for _, secretMatch := range oauth2ClientSecretMatches {

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_GitHubOauth2,
				Raw:          []byte(idMatch[1]),
				SecretParts: map[string]string{
					"id":     idMatch[1],
					"secret": secretMatch[1],
				},
				RawV2: []byte(idMatch[1] + secretMatch[1]),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
			}

			// Verification is delegated so that this path and the verification cache's
			// per-result path share one implementation.
			if verify {
				s.VerifyResult(ctx, &s1)
			}

			results = append(results, s1)
		}
	}

	return
}

// VerifyResult verifies a single client ID / client secret pair.
// the verification cache calls it directly for results that missed the cache, which
// is what keeps a chunk of many pairs from re-verifying pairs whose status is already known.
func (s Scanner) VerifyResult(ctx context.Context, result *detectors.Result) {
	clientID := result.SecretParts["id"]
	clientSecret := result.SecretParts["secret"]
	clientCredentials := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}

	_, err := clientCredentials.Token(ctx)
	// if client id and client secret is correct, it will return bad verification code error as we do not pass any verification code
	// docs: https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-oauth-app-access-token-request-errors#bad-verification-code
	if err != nil && strings.Contains(err.Error(), githubBadVerificationCodeError) {
		// mark result as verified only in case of bad verification code error, for any other error the result will be unverified
		result.Verified = true
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GitHubOauth2
}

func (s Scanner) Description() string {
	return "GitHub OAuth2 credentials are used to authenticate and authorize applications to access GitHub's API on behalf of a user or organization. These credentials include a client ID and client secret, which can be used to obtain access tokens for accessing GitHub resources."
}
