package googleoauth2clientcredentials

import (
	"context"
	"errors"
	"net/http"
	"strings"

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

// Trimmed from Raw, otherwise "google" matches the false positive wordlist.
const clientIDSuffix = ".apps.googleusercontent.com"

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
						Raw:          []byte(strings.TrimSuffix(clientID, clientIDSuffix)),
						RawV2:        []byte(clientID + clientSecret),
						SecretParts: map[string]string{
							"client_id":     clientID,
							"client_secret": clientSecret,
						},
					}

					if verify {
						s.VerifyResult(ctx, &s1)
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
					Raw:          []byte(strings.TrimSuffix(clientID, clientIDSuffix)),
					RawV2:        []byte(clientID),
					SecretParts:  map[string]string{"client_id": clientID},
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
					SecretParts:  map[string]string{"client_secret": clientSecret},
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

// VerifyResult verifies a single client ID / client secret pair.
func (s Scanner) VerifyResult(ctx context.Context, result *detectors.Result) {
	cfg := &oauth2.Config{
		ClientID:     result.SecretParts["client_id"],
		ClientSecret: result.SecretParts["client_secret"],
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost",
	}
	// Google does not support the client_credentials grant, so exchange a bogus auth code instead:
	// a valid client ID and secret returns invalid_grant, an unknown client or wrong secret returns invalid_client.
	_, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.getClient()), "trufflehog")

	var rErr *oauth2.RetrieveError
	if errors.As(err, &rErr) {
		switch rErr.ErrorCode {
		case "invalid_grant":
			result.Verified = true
			return
		case "invalid_client":
			return
		}
	}
	result.SetVerificationError(err, result.SecretParts["client_secret"])
}
