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

var _ detectors.Detector = (*Scanner)(nil)

var (
	oauth2ClientID     = regexp.MustCompile("[0-9a-zA-Z\\-_]{16,}\\.apps\\.googleusercontent\\.com")
	oauth2ClientSecret = regexp.MustCompile("GOCSPX-[0-9a-zA-Z\\-_]{20,}")
)

const (
	gcpOAuthBadVerificationCodeError = "bad_verification_code"
)

func (s Scanner) Keywords() []string {
	return []string{".apps.googleusercontent.com", "GOCSPX-", "oauth2_client_id", "oauth2_client_secret"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoogleOauth2
}

func (s Scanner) Description() string {
	return "GCP OAuth2 credentials are sensitive strings (client ID and secret) issued by Google Cloud to identify your application and securely authorize its access to Google APIs on behalf of users."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	oauth2ClientIDMatches := oauth2ClientID.FindAllStringSubmatch(dataStr, -1)
	oauth2ClientSecretMatches := oauth2ClientSecret.FindAllStringSubmatch(dataStr, -1)

	seen := make(map[string]bool)

	pairedIDs := make(map[string]bool)
	pairedSecrets := make(map[string]bool)

	if len(oauth2ClientIDMatches) > 0 && len(oauth2ClientSecretMatches) > 0 {
		for _, idMatch := range oauth2ClientIDMatches {
			for _, secretMatch := range oauth2ClientSecretMatches {
				clientID := idMatch[0]
				clientSecret := secretMatch[0]
				key := "pair:" + clientID + ":" + clientSecret

				if !seen[key] {
					seen[key] = true
					pairedIDs[clientID] = true
					pairedSecrets[clientSecret] = true

					s1 := detectors.Result{
						DetectorType: detectorspb.DetectorType_GoogleOauth2,
						Raw:          []byte(clientID),
						RawV2:        []byte(clientID + clientSecret),
					}

					if verify {
						config := &clientcredentials.Config{
							ClientID:     clientID,
							ClientSecret: clientSecret,
							TokenURL:     google.Endpoint.TokenURL,
						}
						_, err := config.Token(ctx)
						if err != nil && strings.Contains(err.Error(), gcpOAuthBadVerificationCodeError) {
							s1.Verified = true
						}
					}

					results = append(results, s1)
				}
			}
		}
	}

	// Process orphan ClientID-only matches (not part of any pair)
	if len(oauth2ClientIDMatches) > 0 && len(pairedIDs) == 0 {
		for _, idMatch := range oauth2ClientIDMatches {
			clientID := idMatch[0]
			key := "id:" + clientID

			if !pairedIDs[clientID] && !seen[key] {
				seen[key] = true
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_GoogleOauth2,
					Raw:          []byte(clientID),
					RawV2:        []byte(clientID),
				}
				results = append(results, s1)
			}
		}
	}

	// Process orphan ClientSecret-only matches (not part of any pair)
	if len(oauth2ClientSecretMatches) > 0 && len(pairedSecrets) == 0 {
		for _, secretMatch := range oauth2ClientSecretMatches {
			clientSecret := secretMatch[0]
			key := "secret:" + clientSecret

			if !pairedSecrets[clientSecret] && !seen[key] {
				seen[key] = true
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_GoogleOauth2,
					Raw:          []byte(clientSecret),
					RawV2:        []byte(clientSecret),
				}
				results = append(results, s1)
			}
		}
	}
	return
}
