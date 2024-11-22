package privatekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

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
				extraData          = newExtraData()
				verificationErrors = newVerificationErrors()
			)

			// Look up certificate information.
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := lookupFingerprint(ctx, fingerprint, s.IncludeExpired)
				if err == nil {
					if len(data.CertificateResults) > 0 {
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
				user, err := verifyGitHubUser(ctx, parsedKey)
				if err != nil && !errors.Is(err, errPermissionDenied) {
					verificationErrors.Add(err)
				}
				if user != nil {
					extraData.Add("github_user", "Key can SSH pull/push as user: "+*user)
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
					extraData.Add("gitlab_user", "Key can SSH pull/push as user: "+*user)
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
	driftwoodResult
}

func (r result) GetExtraData() map[string]string {
	data := map[string]string{}
	if len(r.CertificateURLs) > 0 {
		data["certificate_urls"] = strings.Join(r.CertificateURLs, ",")
	}
	if len(r.CertificateResults) > 0 {
		for _, cert := range r.CertificateResults {
			v := reflect.ValueOf(cert)
			t := v.Type()
			for i := 0; i < v.NumField(); i++ {
				field := v.Field(i)
				fieldName := t.Field(i).Name
				// Convert field name to snake_case
				snakeCase := ""
				for i, r := range fieldName {
					if i > 0 && unicode.IsUpper(r) {
						if string(r) == "D" && i > 0 && string(fieldName[i-1]) == "I" {
							snakeCase += string(unicode.ToLower(r))
						} else {
							snakeCase += "_" + string(unicode.ToLower(r))
						}
					} else {
						snakeCase += string(unicode.ToLower(r))
					}
				}
				switch field.Kind() {
				case reflect.String:
					if str := field.String(); str != "" {
						data[snakeCase] = str
					}
				case reflect.Slice:
					if slice := field.Interface(); field.Len() > 0 {
						if strSlice, ok := slice.([]string); ok {
							data[snakeCase] = strings.Join(strSlice, ",")
						}
					}
				case reflect.Struct:
					if !field.IsZero() {
						if timeField, ok := field.Interface().(time.Time); ok {
							data[snakeCase] = timeField.String()
						}
					}
				}
			}
		}
	}
	return data
}

func lookupFingerprint(ctx context.Context, publicKeyFingerprintInHex string, includeExpired bool) (result, error) {
	data := result{}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://keychecker.trufflesecurity.com/fingerprint/%s", publicKeyFingerprintInHex), nil)
	if err != nil {
		return data, err
	}
	res, err := client.Do(req)
	if err != nil {
		return data, err
	}
	defer res.Body.Close()

	results := driftwoodResult{}
	err = json.NewDecoder(res.Body).Decode(&results)
	if err != nil {
		return data, err
	}

	data.driftwoodResult = results

	seen := map[string]struct{}{}
	for _, r := range results.CertificateResults {
		if _, ok := seen[r.CertificateFingerprint]; ok {
			continue
		}
		if !includeExpired && time.Since(r.ExpirationTimestamp) > 0 {
			continue
		}
		data.CertificateURLs = append(data.CertificateURLs, fmt.Sprintf("https://crt.sh/?q=%s", r.CertificateFingerprint))
		seen[r.CertificateFingerprint] = struct{}{}
	}

	return data, nil
}

type driftwoodResult struct {
	CertificateResults []certificateResult `json:"CertificateResults,omitempty"`
}

type certificateResult struct {
	Domains                []string `json:",omitempty"`
	CertificateFingerprint string
	ExpirationTimestamp    time.Time
	IssuerName             string   `json:",omitempty"` // CA information
	SubjectName            string   `json:",omitempty"` // Certificate subject
	IssuerOrganization     []string `json:",omitempty"` // CA organization(s)
	SubjectOrganization    []string `json:",omitempty"` // Subject organization(s)
	KeyUsages              []string `json:",omitempty"` // e.g., ["DigitalSignature", "KeyEncipherment"]
	ExtendedKeyUsages      []string `json:",omitempty"` // e.g., ["ServerAuth", "ClientAuth"]
	SubjectKeyID           string   `json:",omitempty"` // hex encoded
	AuthorityKeyID         string   `json:",omitempty"` // hex encoded
	SerialNumber           string   `json:",omitempty"` // hex encoded
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
