package privatekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/crypto/ssh"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

var (
	falsePositiveGHUsernames = map[detectors.FalsePositive]struct{}{
		// This hack is because it's probably one of the most widely distributed github keys
		// and a frequent annoyance.
		// It is active at the time of this commit, but the developer is unresponsive.
		detectors.FalsePositive("aaron1234567890123"): {},
	}
)

// knownTestKeyFingerprints holds the SHA-1 fingerprints (hex-encoded, matching the
// output of FingerprintPEMKey) of well-known, publicly committed test/example private
// keys. These keys ship unmodified in widely distributed packages and are only used to
// spin up local test servers; they are not real credentials, so flagging them produces
// false positives.
//
// The fingerprints below cover the Node.js core TLS test fixture keys (agent1..4,
// client1..2, proxy1..2, server1..2) that the `tunnel` npm package vendors under
// test/keys/. Those same key files appear in the node_modules of countless downstream
// projects that depend on `tunnel` (e.g. several Azure SDK packages). See
// https://github.com/trufflesecurity/trufflehog/issues/5299.
var knownTestKeyFingerprints = map[string]struct{}{
	"fe7715c7bc2137f36b366fac476c2c29cb9ff885": {}, // agent1-key.pem
	"cfcbaa9f3e475e397d5ea1808fdfef7c961bf03a": {}, // agent2-key.pem
	"64a4d4f9680ddb544a15322acfc3bfba5a7d60eb": {}, // agent3-key.pem
	"e342c159e097a4b79b361c2fd6c8ed42bd6629f3": {}, // agent4-key.pem
	"f788f2bc8d26134c78305a34cb261a881cb105dc": {}, // client1-key.pem
	"eb228c0291c750d2661713d58dd426c8d60d4514": {}, // client2-key.pem
	"2c8a3af664e06fd598b02a108504effab26641e9": {}, // proxy1-key.pem
	"d414f9ed9c2f83e4b7386f38b76eb958d96877df": {}, // proxy2-key.pem
	"7e28ec3dbb3758ba8c60a366a2eda27d5864b674": {}, // server1-key.pem
	"f69f9bfbe4e144689045a01a3466bcb3a39a9aa9": {}, // server2-key.pem
}

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
		token := Normalize(match)
		if len(token) < 64 {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_PrivateKey,
			Raw:          []byte(token),
			Redacted:     token[0:64],
			ExtraData:    make(map[string]string),
			SecretParts:  map[string]string{"token": token},
		}

		// set not normalized match as primary secret value so it is used to calculate line of code
		s1.SetPrimarySecretValue(match)

		var passphrase string
		parsedKey, err := ssh.ParseRawPrivateKey([]byte(token))
		if err != nil && strings.Contains(err.Error(), "private key is passphrase protected") {
			s1.ExtraData["encrypted"] = "true"
			parsedKey, passphrase, err = Crack([]byte(token))
			if err != nil {
				// The key is encrypted and the passphrase could not be
				// recovered from the wordlist. It still represents a real
				// exposure (offline-crackable, weak/legacy KDFs, passphrase
				// often reused or committed nearby), so surface it as an
				// unverified finding instead of dropping it silently.
				s1.SetVerificationError(err, token)
				results = append(results, s1)
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

		// Skip well-known, publicly committed test/example keys that are shipped
		// unmodified in widely distributed packages. They are not real credentials and
		// flagging them produces false positives.
		if _, known := knownTestKeyFingerprints[fingerprint]; known {
			continue
		}

		if verify {
			var (
				wg                 sync.WaitGroup
				extraData          = newExtraData()
				verificationErrors = NewVerificationErrors(3)
			)

			// Look up certificate information.
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := lookupFingerprintCertificateUrls(ctx, fingerprint, s.IncludeExpired)
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
				username, err := VerifyGitHubUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if username != nil {
					isFalsePositive, _ := detectors.IsKnownFalsePositive(*username, falsePositiveGHUsernames, false)
					if !isFalsePositive {
						extraData.Add("github_user", *username)
					}
				}
			}()

			// Test SSH key against gitlab.com
			wg.Add(1)
			go func() {
				defer wg.Done()
				user, err := VerifyGitLabUser(ctx, parsedKey)
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
			if len(verificationErrors.Errors) > 0 {
				s1.SetVerificationError(fmt.Errorf("verification failures: %s", strings.Join(verificationErrors.Errors, ", ")), token)
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
}

func lookupFingerprintCertificateUrls(
	ctx context.Context,
	publicKeyFingerprintInHex string,
	includeExpired bool,
) (*result, error) {
	results, err := LookupFingerprint(
		ctx,
		publicKeyFingerprintInHex,
	)
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

func LookupFingerprint(ctx context.Context, publicKeyFingerprintInHex string) (*DriftwoodResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	results := DriftwoodResult{}
	err = json.NewDecoder(res.Body).Decode(&results)
	if err != nil {
		return nil, err
	}
	return &results, nil
}

type DriftwoodResult struct {
	CertificateResults []struct {
		Domains                []string  `json:",omitempty"`
		CertificateFingerprint string    `json:"CertificateFingerprint"`
		ExpirationTimestamp    time.Time `json:"ExpirationTimestamp"`
		IssuerName             string    `json:",omitempty"` // CA information
		SubjectName            string    `json:",omitempty"` // Certificate subject
		IssuerOrganization     []string  `json:",omitempty"` // CA organization(s)
		SubjectOrganization    []string  `json:",omitempty"` // Subject organization(s)
		KeyUsages              []string  `json:",omitempty"` // e.g., ["DigitalSignature", "KeyEncipherment"]
		ExtendedKeyUsages      []string  `json:",omitempty"` // e.g., ["ServerAuth", "ClientAuth"]
		SubjectKeyID           string    `json:",omitempty"` // hex encoded
		AuthorityKeyID         string    `json:",omitempty"` // hex encoded
		SerialNumber           string    `json:",omitempty"` // hex encoded
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

type VerificationErrors struct {
	mutex  sync.Mutex
	Errors []string
}

func NewVerificationErrors(capacity int) *VerificationErrors {
	return &VerificationErrors{
		Errors: make([]string, 0, capacity),
	}
}

func (e *VerificationErrors) Add(err error) {
	e.mutex.Lock()
	e.Errors = append(e.Errors, err.Error())
	e.mutex.Unlock()
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PrivateKey
}
