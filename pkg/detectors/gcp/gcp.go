package gcp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"

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
		// This is an unprivileged service account used in Kubernetes' tests. It is intentionally public.
		// https://github.com/kubernetes/kubernetes/blob/10a06602223eab17e02e197d1da591727c756d32/test/e2e_node/runtime_conformance_test.go#L50
		if bytes.Equal(raw, []byte("image-pulling@authenticated-image-pulling.iam.gserviceaccount.com")) {
			continue
		}

		credBytes, _ := json.Marshal(creds)

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_GCP,
			Raw:          raw,
			RawV2:        credBytes,
			Redacted:     creds.ClientEmail,
		}
		// Set the RotationGuideURL in the ExtraData.
		s.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
			"project":        creds.ProjectID,
		}

		if verify {
			s.Verified = isValidGCPServiceAccountKey(ctx, client, creds)
		}

		results = append(results, s)
	}

	return
}

// isValidGCPServiceAccountKey checks if the provided GCP service account key is valid. It verifies this by
// comparing the public key extracted from the certificate retrieved from the `ClientX509CertURL`
// with the public key derived from the `PrivateKey` field of the `gcpKey` struct. If the public keys
// match, the function returns true, indicating a valid service account key. Otherwise, it returns false.
//
// Note: If the service account is expired or disabled, the request to fetch the certificate from the
// `ClientX509CertURL` will fail with a 404 status code. In this case, the function will return false,
// indicating that the service account key is invalid, regardless of the public key comparison.
func isValidGCPServiceAccountKey(ctx context.Context, client *http.Client, key gcpKey) bool {
	certPEM, ok := fetchCert(ctx, client, key.ClientX509CertURL)
	if !ok {
		return false
	}

	publicKey, ok := extractPublicKeyFromCert(certPEM)
	if !ok {
		return false
	}

	privateKey, ok := extractPrivateKey(key.PrivateKey)
	if !ok {
		return false
	}

	k, ok := privateKey.Public().(*rsa.PublicKey)
	if !ok {
		return false
	}

	return publicKey.Equal(k)
}

// fetchCert downloads the certificate from the specified URL and returns its PEM-encoded string.
func fetchCert(ctx context.Context, client *http.Client, url string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}

	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		return "", false
	}
	defer res.Body.Close()

	var resp map[string]string
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", false
	}

	// Assuming the certificate is the first value in the response.
	for _, certPEM := range resp {
		return strings.TrimSpace(certPEM), true
	}

	return "", false
}

// extractPublicKeyFromCert decodes the PEM-encoded certificate to extract the RSA public key.
func extractPublicKeyFromCert(certPEM string) (*rsa.PublicKey, bool) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, false
	}

	return publicKey, true
}

// extractPrivateKey decodes the PEM-encoded private key to extract the RSA private key.
func extractPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, bool) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, false
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, false
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, false
	}

	return rsaPrivateKey, true
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GCP
}
