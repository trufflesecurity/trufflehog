package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"golang.org/x/oauth2/google"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

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

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("provider_x509")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAll(data, -1)

	for _, match := range matches {
		key := bytes.ReplaceAll(match, []byte(`,\n`), []byte(`\n`))
		key = bytes.ReplaceAll(key, []byte(`"\n`), []byte(`\n`))
		key = bytes.ReplaceAll(key, []byte(`\"`), []byte(`"`))

		creds := gcpKey{}
		err := json.Unmarshal(key, &creds)
		if err != nil {
			continue
		}

		// for Slack mangling (mailto scheme and hyperlinks)
		if strings.Contains(creds.ClientEmail, `<mailto:`) {
			creds.ClientEmail = strings.Split(strings.Split(creds.ClientEmail, `<mailto:`)[1], `|`)[0]
		}
		creds.AuthProviderX509CertURL = string(trimCarrots([]byte(creds.AuthProviderX509CertURL)))
		creds.AuthURI = string(trimCarrots([]byte(creds.AuthURI)))
		creds.ClientX509CertURL = string(trimCarrots([]byte(creds.ClientX509CertURL)))
		creds.TokenURI = string(trimCarrots([]byte(creds.TokenURI)))

		raw := []byte(creds.ClientEmail)
		if len(raw) == 0 {
			raw = key
		}

		credBytes, _ := json.Marshal(creds)

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_GCP,
			Raw:          raw,
			RawV2:        credBytes,
			Redacted:     creds.ClientEmail,
		}

		if verify {
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

func trimCarrots(s []byte) []byte {
	s = bytes.TrimPrefix(s, []byte("<"))
	s = bytes.TrimSuffix(s, []byte(">"))
	return s
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GCP
}
