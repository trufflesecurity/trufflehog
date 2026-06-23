package duoapisecretkey

import (
	"context"
	"fmt"
	"io"
	"net/http"

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
	// Duo API Secret Key is a 40-character hex string
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo", "secret"}) + `\b([a-fA-F0-9]{40})\b`)
	// Duo Integration Key is a 20-character alphanumeric string
	integrationPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo", "integration"}) + `\b(DI[A-Z0-9]{18})\b`)
	// Duo API hostname pattern
	hostPat = regexp.MustCompile(`\b(api-[a-f0-9]{8}\.duosecurity\.com)\b`)
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
	// Duo Admin API check endpoint
	url := fmt.Sprintf("https://%s/admin/v1/info/summary", host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, err
	}

	// Duo uses HTTP Basic Auth with integration key as username and secret key as password
	req.SetBasicAuth(integration, secret)

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
			"rotation_guide": "https://howtorotate.com/docs/tutorials/duo/",
		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The secret is determinately not verified
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DuoAPISecretKey
}

func (s Scanner) Description() string {
	return "Duo Security provides multi-factor authentication and access security services. Duo API keys consist of an integration key, secret key, and API hostname used to access Duo Admin API and Auth API endpoints."
}
