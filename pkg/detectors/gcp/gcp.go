package gcp

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"golang.org/x/oauth2/google"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\{[^{]+auth_provider_x509_cert_url[^}]+\}`)
)

type gcpKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

func trimCarrots(s string) string {
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"provider_x509"}
}

// FromData will find and optionally verify GCP secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {
		key := match

		key = strings.ReplaceAll(key, `,\\n`, `\n`)
		key = strings.ReplaceAll(key, `\"\\n`, `\n`)
		key = strings.ReplaceAll(key, `\\"`, `"`)

		creds := gcpKey{}
		err := json.Unmarshal([]byte(key), &creds)
		if err != nil {
			continue
		}

		// for Slack mangling (mailto scheme and hyperlinks)
		if strings.Contains(creds.ClientEmail, `<mailto:`) {
			creds.ClientEmail = strings.Split(strings.Split(creds.ClientEmail, `<mailto:`)[1], `|`)[0]
		}
		creds.AuthProviderX509CertURL = trimCarrots(creds.AuthProviderX509CertURL)
		creds.AuthURI = trimCarrots(creds.AuthURI)
		creds.ClientX509CertURL = trimCarrots(creds.ClientX509CertURL)
		creds.TokenURI = trimCarrots(creds.TokenURI)

		// Not sure why this might happen, but we've observed this with a verified cred
		raw := []byte(creds.ClientEmail)
		if len(raw) == 0 {
			raw = []byte(key)
		}

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_GCP,
			Raw:          raw,
			Redacted:     creds.ClientEmail,
		}

		if verify {
			credBytes, _ := json.Marshal(creds)
			credentials, err := google.CredentialsFromJSON(ctx, credBytes, "https://www.googleapis.com/auth/cloud-platform")
			if err != nil {
				continue
			}
			if credentials != nil {
				_, err = credentials.TokenSource.Token()
				if err == nil {
					s.Verified = true
				}
			}
		}

		results = append(results, s)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GCP
}
