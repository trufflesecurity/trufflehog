package privatekey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"golang.org/x/crypto/ssh"
)

type Scanner struct {
	IncludeExpired bool
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// TODO: add base64 encoded key support
	client = common.RetryableHttpClient()
	keyPat = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"private key"}
}

// FromData will find and optionally verify Privatekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	results := []detectors.Result{}
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)

	for _, match := range matches {

		token := normalize(match)

		if len(token) < 64 {
			continue
		}

		secret := detectors.Result{
			DetectorType: detectorspb.DetectorType_PrivateKey,
			Raw:          []byte(token),
			Redacted:     token[0:64],
		}

		secret.ExtraData = make(map[string]string)

		var passphrase string
		parsedKey, err := ssh.ParseRawPrivateKey([]byte(token))
		if err != nil && strings.Contains(err.Error(), "private key is passphrase protected") {
			secret.ExtraData["encrypted"] = "true"
			parsedKey, passphrase, err = crack([]byte(token))
			if err != nil {
				secret.VerificationError = err
				continue
			}
			if passphrase != "" {
				secret.ExtraData["cracked_encryption_passphrase"] = "true"
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
			verificationErrors := []string{}
			data, err := lookupFingerprint(fingerprint, s.IncludeExpired)
			if err == nil {
				if data != nil {
					secret.Verified = true
					secret.ExtraData["certificate_urls"] = strings.Join(data.CertificateURLs, ", ")
				}
			} else {
				verificationErrors = append(verificationErrors, err.Error())
			}

			user, err := verifyGitHubUser(parsedKey)
			if err != nil && !errors.Is(err, errPermissionDenied) {
				verificationErrors = append(verificationErrors, err.Error())
			}
			if user != nil {
				secret.Verified = true
				secret.ExtraData["github_user"] = *user
			}

			user, err = verifyGitLabUser(parsedKey)
			if err != nil && !errors.Is(err, errPermissionDenied) {
				verificationErrors = append(verificationErrors, err.Error())
			}
			if user != nil {
				secret.Verified = true
				secret.ExtraData["gitlab_user"] = *user
			}

			if !secret.Verified && len(verificationErrors) > 0 {
				secret.VerificationError = fmt.Errorf("verification failures: %s", strings.Join(verificationErrors, ", "))
			}
		}

		if len(secret.ExtraData) == 0 {
			secret.ExtraData = nil
		}

		results = append(results, secret)
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PrivateKey
}
