package gcpoauth2

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/google"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// GCP Oauth2 Client ID and secret regex patterns.
var (
	oauth2ClientID     = regexp.MustCompile("[0-9a-zA-Z\\-_]{16,}\\.apps\\.googleusercontent\\.com")
	oauth2ClientSecret = regexp.MustCompile("GOCSPX-[0-9a-zA-Z\\-_]{20,}")
)

const (
	gcpOAuthBadVerificationCodeError = "bad_verification_code"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".apps.googleusercontent.com", "GOCSPX-"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoogleOauth2
}

func (s Scanner) Description() string {
	return "GCP OAuth2 credentials are sensitive strings (client ID and secret) issued by Google Cloud to identify your application and securely authorize its access to Google APIs on behalf of users."
}

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Oauth2 client ID and secret
	oauth2ClientIDMatches := oauth2ClientID.FindAllStringSubmatch(dataStr, -1)
	oauth2ClientSecretMatches := oauth2ClientSecret.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range oauth2ClientIDMatches {
		for _, secretMatch := range oauth2ClientSecretMatches {

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GoogleOauth2,
				Raw:          []byte(idMatch[1]),
				RawV2:        []byte(idMatch[1] + secretMatch[1]),
			}

			config := &clientcredentials.Config{
				ClientID:     idMatch[1],
				ClientSecret: secretMatch[1],
				TokenURL:     google.Endpoint.TokenURL,
			}
			if verify {
				_, err := config.Token(ctx)
				// if client id and client secret is correct, it will return bad verification code error as we do not pass any verification code
				if err != nil && strings.Contains(err.Error(), gcpOAuthBadVerificationCodeError) {
					// mark result as verified only in case of bad verification code error, for any other error the result will be unverified
					s1.Verified = true
				}
			}

			results = append(results, s1)
		}
	}

	return
}
