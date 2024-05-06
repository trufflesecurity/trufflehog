package privatekey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
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
				extraData          = newExtraData()
				verificationErrors = newVerificationErrors()
			)

			// Look up certificate information.
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := lookupFingerprint(fingerprint, s.IncludeExpired)
				if err == nil {
					if data != nil {
						extraData.Add("certificate_urls", strings.Join(data.CertificateURLs, ", "))
					}
				} else {
					verificationErrors.Add(err)
				}
			}()

			// Test SSH key against github.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := verifyGitHubUser(parsedKey)
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
				user, err := verifyGitLabUser(parsedKey)
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

type result struct {
	CertificateURLs []string
	GitHubUsername  string
}

func lookupFingerprint(publicKeyFingerprintInHex string, includeExpired bool) (*result, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
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

	var data *result

	seen := map[string]struct{}{}
	for _, r := range results.CertificateResults {
		if _, ok := seen[r.CertificateFingerprint]; ok {
			continue
		}
		if !includeExpired && time.Since(r.ExpirationTimestamp) > 0 {
			continue
		}
		if data == nil {
			data = &result{}
		}
		data.CertificateURLs = append(data.CertificateURLs, fmt.Sprintf("https://crt.sh/?q=%s", r.CertificateFingerprint))
		seen[r.CertificateFingerprint] = struct{}{}
	}

	return data, nil
}

type DriftwoodResult struct {
	CertificateResults []struct {
		CertificateFingerprint string    `json:"CertificateFingerprint"`
		ExpirationTimestamp    time.Time `json:"ExpirationTimestamp"`
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
