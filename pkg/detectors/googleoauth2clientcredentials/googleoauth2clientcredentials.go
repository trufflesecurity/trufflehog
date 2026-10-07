package googleoauth2clientcredentials

import (
	"context"
	"errors"
	"net/http"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var defaultClient = common.SaneHttpClient()

var (
	oauth2ClientID     = regexp.MustCompile("[0-9a-zA-Z\\-_]{16,}\\.apps\\.googleusercontent\\.com")
	oauth2ClientSecret = regexp.MustCompile("GOCSPX-[0-9a-zA-Z\\-_]{20,}")
)

func (s Scanner) Keywords() []string {
	return []string{".apps.googleusercontent.com", "GOCSPX-", "oauth2_client_id", "oauth2_client_secret"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GoogleOauth2ClientCredentials
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
						DetectorType: detector_typepb.DetectorType_GoogleOauth2ClientCredentials,
						Raw:          []byte(clientID),
						RawV2:        []byte(clientID + clientSecret),
					}

					if verify {
						verified, vErr := verifyMatch(ctx, s.getClient(), clientID, clientSecret)
						s1.Verified = verified
						s1.SetVerificationError(vErr, clientSecret)
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
					DetectorType: detector_typepb.DetectorType_GoogleOauth2ClientCredentials,
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
					DetectorType: detector_typepb.DetectorType_GoogleOauth2ClientCredentials,
					Raw:          []byte(clientSecret),
					RawV2:        []byte(clientSecret),
				}
				results = append(results, s1)
			}
		}
	}
	return
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Google does not support the client_credentials grant, so exchange a bogus auth code instead:
// a valid client ID and secret returns invalid_grant, an unknown client or wrong secret returns invalid_client.
func verifyMatch(ctx context.Context, client *http.Client, clientID, clientSecret string) (bool, error) {
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost",
	}
	_, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, client), "trufflehog")

	var rErr *oauth2.RetrieveError
	if !errors.As(err, &rErr) {
		return false, err
	}
	switch rErr.ErrorCode {
	case "invalid_grant":
		return true, nil
	case "invalid_client":
		return false, nil
	default:
		return false, err
	}
}
