package privatekey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	IncludeExpired bool
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.RetryableHttpClient()
	keyPat = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("private key")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	results := []detectors.Result{}

	matches := keyPat.FindAll(data, -1)

	for _, match := range matches {
		token := normalize(match)

		if len(token) < 64 {
			continue
		}

		secret := detectors.Result{
			DetectorType: detectorspb.DetectorType_PrivateKey,
			Raw:          token,
			Redacted:     string(token[0:64]),
		}

		fingerprint, err := FingerprintPEMKey([]byte(token))
		if err != nil {
			continue
		}

		if verify {
			data, err := lookupFingerprint(string(fingerprint), s.IncludeExpired)
			if err == nil {
				secret.StructuredData = data
				if data != nil {
					secret.Verified = true
				}
			}
		}

		results = append(results, secret)
	}

	return results, nil
}

func lookupFingerprint(publicKeyFingerprintInHex string, includeExpired bool) (data *detectorspb.StructuredData, err error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
	if err != nil {
		return
	}
	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	results := DriftwoodResult{}
	err = json.NewDecoder(res.Body).Decode(&results)
	if err != nil {
		return
	}

	seen := make(map[string]struct{})
	for _, r := range results.CertificateResults {
		if _, ok := seen[r.CertificateFingerprint]; ok {
			continue
		}
		if !includeExpired && time.Since(r.ExpirationTimestamp) > 0 {
			continue
		}
		if data == nil {
			data = &detectorspb.StructuredData{}
		}
		if data.TlsPrivateKey == nil {
			data.TlsPrivateKey = make([]*detectorspb.TlsPrivateKey, 0)
		}
		data.TlsPrivateKey = append(data.TlsPrivateKey, &detectorspb.TlsPrivateKey{
			CertificateFingerprint: r.CertificateFingerprint,
			ExpirationTimestamp:    r.ExpirationTimestamp.Unix(),
			VerificationUrl:        fmt.Sprintf("https://crt.sh/?q=%s", r.CertificateFingerprint),
		})
		seen[r.CertificateFingerprint] = struct{}{}
	}

	for _, r := range results.GitHubSSHResults {
		if _, ok := seen[r.Username]; ok {
			continue
		}
		if data == nil {
			data = &detectorspb.StructuredData{}
		}
		if data.GithubSshKey == nil {
			data.GithubSshKey = make([]*detectorspb.GitHubSSHKey, 0)
		}
		data.GithubSshKey = append(data.GithubSshKey, &detectorspb.GitHubSSHKey{
			User: r.Username,
		})
		seen[r.Username] = struct{}{}
	}

	return
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
