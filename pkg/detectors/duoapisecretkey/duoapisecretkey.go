package duoapisecretkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Duo API Secret Key is a 40-character alphanumeric string
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo", "secret"}) + `\b([a-zA-Z0-9]{40})\b`)
	// Duo Integration Key is a 20-character alphanumeric string starting with DI
	integrationPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo", "integration"}) + `\b(DI[A-Z0-9]{18})\b`)
	// Duo API hostname pattern
	hostPat = regexp.MustCompile(`\b(api-[a-z0-9]{8}\.duosecurity\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"duo", "duosecurity", "secret", "integration"}
}

// FromData will find and optionally verify Duoapisecretkey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Find all secret keys
	secretMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	// Find all integration keys
	integrationMatches := make(map[string]struct{})
	for _, match := range integrationPat.FindAllStringSubmatch(dataStr, -1) {
		integrationMatches[match[1]] = struct{}{}
	}

	// Find all API hostnames
	hostMatches := make(map[string]struct{})
	for _, match := range hostPat.FindAllStringSubmatch(dataStr, -1) {
		hostMatches[match[1]] = struct{}{}
	}

	// Duo requires secret key, integration key, and API hostname for verification
	for secret := range secretMatches {
		for integration := range integrationMatches {
			for host := range hostMatches {
				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_DuoAPISecretKey,
					Raw:          []byte(secret),
					SecretParts: map[string]string{
						"secret":      secret,
						"integration": integration,
						"host":        host,
					},
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, extraData, verificationErr := verifyMatch(ctx, client, secret, integration, host)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					s1.SetVerificationError(verificationErr, secret)
				}

				results = append(results, s1)
			}
		}
	}

	// Also return unverified secrets even if we don't have all parts
	if len(results) == 0 {
		for secret := range secretMatches {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_DuoAPISecretKey,
				Raw:          []byte(secret),
				SecretParts:  map[string]string{"secret": secret},
			}
			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, secret, integration, host string) (bool, map[string]string, error) {
	// Use Duo Auth API check endpoint with signed request
	method := "GET"
	path := "/auth/v2/check"
	params := ""

	date := time.Now().UTC().Format(time.RFC1123)
	url := fmt.Sprintf("https://%s%s", host, path)

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return false, nil, err
	}

	// Add Duo signature authentication headers
	auth := signDuoRequest(integration, secret, method, host, path, params, date)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Date", date)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, map[string]string{
			"rotation_guide": "https://duo.com/docs/administration-applications#rotating-keys",
		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The secret is determinately not verified
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// signDuoRequest creates the Authorization header for Duo API requests using HMAC-SHA1
// Reference: https://duo.com/docs/authapi#authentication
func signDuoRequest(integration, secret, method, host, path, params, date string) string {
	// Build canonical string
	canon := []string{
		date,
		strings.ToUpper(method),
		strings.ToLower(host),
		path,
		params,
	}
	canonical := strings.Join(canon, "\n")

	// Compute HMAC-SHA1 signature (hex-encoded, not base64)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Create Basic Auth: base64(integration_key:hex_signature)
	auth := integration + ":" + signature
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	return basicAuth
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DuoAPISecretKey
}

func (s Scanner) Description() string {
	return "Duo Security provides multi-factor authentication and access security services. Duo API keys consist of an integration key, secret key, and API hostname used to access Duo Admin API and Auth API endpoints."
}
