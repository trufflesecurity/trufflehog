package gcp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)
var _ detectors.StartOffsetProvider = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat        = regexp.MustCompile(`\{[^{]+auth_provider_x509_cert_url[^}]+\}`)
	privateKeyPat = regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[a-zA-Z0-9+/=\\s]+-----END PRIVATE KEY-----`)
	x509UrlPat    = regexp.MustCompile(`https://www\.googleapis\.com/robot/v1/metadata/x509/[^"]+`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"provider_x509"}
}

const maxGCPKeySize = 2048

// MaxSecretSize returns the maximum size of a secret that this detector can find.
func (Scanner) MaxSecretSize() int64 { return maxGCPKeySize }

const startOffset = 4096

// StartOffset returns the start offset for the secret this detector finds.
func (Scanner) StartOffset() int64 { return startOffset }

// FromData will find and optionally verify GCP secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keys := keyPat.FindAllString(dataStr, -1)

	for _, key := range keys {
		// find private key and x509 url from the key
		privateKeyPEM := privateKeyPat.FindString(key)
		x509URL := x509UrlPat.FindString(key)

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_GCP,
			Raw:          []byte(x509URL),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
			},
		}

		if verify {
			isVerified, verificationErr := s.verifyGCP(ctx, privateKeyPEM, x509URL)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GCP
}

func (s Scanner) Description() string {
	return "GCP (Google Cloud Platform) is a suite of cloud computing services that runs on the same infrastructure that Google uses internally for its end-user products. GCP keys can be used to access and manage these services."
}

// getPublicKeys make a GET call to the provided x509Url and get the signed public keys
func getPublicKeys(ctx context.Context, client *http.Client, x509Url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x509Url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// decode the JSON response
		var publicKeys map[string]string

		if err = json.NewDecoder(resp.Body).Decode(&publicKeys); err != nil {
			return nil, fmt.Errorf("error decoding JSON response: %v", err)
		}

		return publicKeys, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("no public keys found for x509 URL: %s", x509Url)
	default:
		return map[string]string{}, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) verifyGCP(ctx context.Context, privateKeyPEM, x509URL string) (bool, error) {
	if privateKeyPEM == "" || x509URL == "" {
		return false, nil // skip this key if private key or x509 URL is missing
	}

	// make a call to x509 URL to get the signed public keys
	publicKeysMap, err := getPublicKeys(ctx, s.getClient(), x509URL)
	if err != nil {
		return false, err
	}

	// parse the private key
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return false, err
	}

	// loop over all public keys and compare them with private key
	for _, publicKeyPEM := range publicKeysMap {
		publicKey, err := parseRSAPublicKey(publicKeyPEM)
		if err != nil {
			continue
		}

		// if any keys match, return verified as true
		if compareKeys(privateKey, publicKey) {
			return true, nil
		}
	}

	return false, fmt.Errorf("private key didn't match with any public keys from client_x509_cert_url: %s", x509URL)
}

// parseRSAPrivateKey parse RSA private key from PEM
func parseRSAPrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// decode the private key (PKCS#1 or PKCS#8)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
	}

	return privateKey.(*rsa.PrivateKey), nil
}

// parseRSAPublicKey parse RSA public key from x509 certificate (PEM encoded)
func parseRSAPublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || !strings.Contains(block.Type, "CERTIFICATE") {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// parse the x509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %v", err)
	}

	// extract and return the public key as *rsa.PublicKey
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return publicKey, nil
}

// compareKeys compare RSA private key and public key
func compareKeys(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) bool {
	// compare the modulus (N) of the private key and public key
	return privateKey.PublicKey.N.Cmp(publicKey.N) == 0
}
