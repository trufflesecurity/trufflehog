package privatekey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/crypto/ssh"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	IncludeExpired bool
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)

var (
	// TODO: add base64 encoded key support
	client = common.RetryableHTTPClient()
	keyPat = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"private key"}
}

const maxPrivateKeySize = 4096

// ProvideMaxSecretSize returns the maximum size of a secret that this detector can find.
func (s Scanner) MaxSecretSize() int64 { return maxPrivateKeySize }

// FromData will find and optionally verify Privatekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)
	for _, match := range matches {
		token := normalize(match)
		if len(token) < 64 {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PrivateKey,
			Raw:          []byte(token),
			Redacted:     token[0:64],
			ExtraData:    make(map[string]string),
		}

		var passphrase string
		parsedKey, err := ssh.ParseRawPrivateKey([]byte(token))
		if err != nil && strings.Contains(err.Error(), "private key is passphrase protected") {
			s1.ExtraData["encrypted"] = "true"
			parsedKey, passphrase, err = crack([]byte(token))
			if err != nil {
				s1.SetVerificationError(err, token)
				continue
			}
			if passphrase != "" {
				s1.ExtraData["cracked_encryption_passphrase"] = "true"
			}
		} else if err != nil {
			// couldn't parse key, probably invalid
			continue
		}

		fingerprint, err := FingerprintPEMKey(parsedKey)
		if err != nil {
			continue
		}

		if verify {
			var (
				wg                 sync.WaitGroup
				verificationErrors = newVerificationErrors()
				extraData          = newExtraData()
			)

			// Look up certificate information.
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := lookupFingerprint(ctx, fingerprint, s.IncludeExpired)
				if err == nil {
					if data != nil {
						if len(data.CertificateURLs) > 0 {
							extraData.Add("certificate_urls", strings.Join(data.CertificateURLs, ", "))
						}

						// Inlcude certificate details in the extra data.
						for i, cert := range data.CertDetails {
							prefix := fmt.Sprintf("cert_%d_", i)
							extraData.Add(prefix+"fingerprint", cert.CertificateFingerprint)
							extraData.Add(prefix+"expiration", cert.ExpirationTimestamp.Format(time.RFC3339))
							if cert.IssuerName != "" {
								extraData.Add(prefix+"issuer_name", cert.IssuerName)
							}
							if cert.SubjectName != "" {
								extraData.Add(prefix+"subject_name", cert.SubjectName)
							}
							if len(cert.IssuerOrganization) > 0 {
								extraData.Add(prefix+"issuer_org", strings.Join(cert.IssuerOrganization, ", "))
							}
							if len(cert.SubjectOrganization) > 0 {
								extraData.Add(prefix+"subject_org", strings.Join(cert.SubjectOrganization, ", "))
							}
							if len(cert.KeyUsages) > 0 {
								extraData.Add(prefix+"key_usages", strings.Join(cert.KeyUsages, ", "))
							}
							if len(cert.ExtendedKeyUsages) > 0 {
								extraData.Add(prefix+"extended_key_usages", strings.Join(cert.ExtendedKeyUsages, ", "))
							}
							if cert.SubjectKeyID != "" {
								extraData.Add(prefix+"subject_key_id", cert.SubjectKeyID)
							}
							if cert.AuthorityKeyID != "" {
								extraData.Add(prefix+"authority_key_id", cert.AuthorityKeyID)
							}
							if cert.SerialNumber != "" {
								extraData.Add(prefix+"serial_number", cert.SerialNumber)
							}
						}
					}
				} else {
					verificationErrors.Add(err)
				}
			}()

			// Test SSH key against github.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := verifyGitHubUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if user != nil {
					extraData.Add("github_user", *user)
				}
			}()

			// Test SSH key against gitlab.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := verifyGitLabUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if user != nil {
					extraData.Add("gitlab_user", *user)
				}
			}()

			wg.Wait()
			if len(extraData.data) > 0 {
				s1.Verified = true
				for k, v := range extraData.data {
					s1.ExtraData[k] = v
				}
			} else {
				s1.ExtraData = nil
			}
			if len(verificationErrors.errors) > 0 {
				s1.SetVerificationError(fmt.Errorf("verification failures: %s", strings.Join(verificationErrors.errors, ", ")), token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Description() string {
	return "Private keys are used for securely connecting and authenticating to various systems and services. Exposure of private keys can lead to unauthorized access and data breaches."
}

type result struct {
	CertificateURLs []string
	GitHubUsername  string
	CertDetails     []certDetails
}

type certDetails struct {
	CertificateFingerprint string
	ExpirationTimestamp    time.Time
	IssuerName             string
	SubjectName            string
	IssuerOrganization     []string
	SubjectOrganization    []string
	KeyUsages              []string
	ExtendedKeyUsages      []string
	SubjectKeyID           string
	AuthorityKeyID         string
	SerialNumber           string
}

func lookupFingerprint(ctx context.Context, publicKeyFingerprintInHex string, includeExpired bool) (*result, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	results := DriftwoodResult{}
	err = json.NewDecoder(res.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	data := result{CertDetails: make([]certDetails, 0)}

	seen := map[string]struct{}{}
	for _, r := range results.CertificateResults {
		if _, ok := seen[r.CertificateFingerprint]; ok {
			continue
		}
		if !includeExpired && time.Since(r.ExpirationTimestamp) > 0 {
			continue
		}

		data.CertificateURLs = append(data.CertificateURLs, fmt.Sprintf("https://crt.sh/?q=%s", r.CertificateFingerprint))

		// Note: Driftwood may not provide all certificate details in the results.
		data.CertDetails = append(data.CertDetails, certDetails{
			CertificateFingerprint: r.CertificateFingerprint,
			ExpirationTimestamp:    r.ExpirationTimestamp,
			IssuerName:             r.IssuerName,
			SubjectName:            r.SubjectName,
			IssuerOrganization:     r.IssuerOrganization,
			SubjectOrganization:    r.SubjectOrganization,
			KeyUsages:              r.KeyUsages,
			ExtendedKeyUsages:      r.ExtendedKeyUsages,
			SubjectKeyID:           r.SubjectKeyID,
			AuthorityKeyID:         r.AuthorityKeyID,
			SerialNumber:           r.SerialNumber,
		})

		seen[r.CertificateFingerprint] = struct{}{}
	}

	return &data, nil
}

type DriftwoodResult struct {
	CertificateResults []struct {
		CertificateFingerprint string    `json:"CertificateFingerprint"`
		ExpirationTimestamp    time.Time `json:"ExpirationTimestamp"`
		IssuerName             string    `json:"IssuerName,omitempty"`          // CA information
		SubjectName            string    `json:"SubjectName,omitempty"`         // Certificate subject
		IssuerOrganization     []string  `json:"IssuerOrganization,omitempty"`  // CA organization(s)
		SubjectOrganization    []string  `json:"SubjectOrganization,omitempty"` // Subject organization(s)
		KeyUsages              []string  `json:"KeyUsages,omitempty"`           // e.g., ["DigitalSignature", "KeyEncipherment"]
		ExtendedKeyUsages      []string  `json:"ExtendedKeyUsages,omitempty"`   // e.g., ["ServerAuth", "ClientAuth"]
		SubjectKeyID           string    `json:"SubjectKeyID,omitempty"`        // hex encoded
		AuthorityKeyID         string    `json:"AuthorityKeyID,omitempty"`      // hex encoded
		SerialNumber           string    `json:"SerialNumber,omitempty"`        // hex encoded
	} `json:"CertificateResults"`
	GitHubSSHResults []struct {
		Username string `json:"Username"`
	} `json:"GitHubSSHResults"`
}

type extraData struct {
	mutex sync.Mutex
	data  map[string]string
}

func newExtraData() *extraData {
	return &extraData{
		data: make(map[string]string),
	}
}

func (e *extraData) Add(key string, value string) {
	e.mutex.Lock()
	e.data[key] = value
	e.mutex.Unlock()
}

type verificationErrors struct {
	mutex  sync.Mutex
	errors []string
}

func newVerificationErrors() *verificationErrors {
	return &verificationErrors{
		errors: make([]string, 0, 3),
	}
}

func (e *verificationErrors) Add(err error) {
	e.mutex.Lock()
	e.errors = append(e.errors, err.Error())
	e.mutex.Unlock()
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PrivateKey
}
