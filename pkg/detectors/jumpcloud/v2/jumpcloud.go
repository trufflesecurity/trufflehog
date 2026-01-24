package jumpcloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	client = common.SaneHttpClient()

	// JumpCloud API keys with jca_ prefix: jca_ + 36 alphanumeric characters (40 total)
	// Example: jca_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
	keyPat = regexp.MustCompile(`\bjca_([a-zA-Z0-9]{36})\b`)

	// Patterns to filter out false positives
	onlyDigits = regexp.MustCompile(`^[0-9]+$`)
	onlyLower  = regexp.MustCompile(`^[a-z]+$`)
	onlyUpper  = regexp.MustCompile(`^[A-Z]+$`)
	sequential = regexp.MustCompile(`^(0123456789|1234567890|abcdefghij|ABCDEFGHIJ)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jca_"}
}

// isLikelyFalsePositive checks if the key portion looks like a placeholder or test value
func isLikelyFalsePositive(key string) bool {
	// Only digits (e.g., 0000000000... or 1234567890...)
	if onlyDigits.MatchString(key) {
		return true
	}
	// Only lowercase letters
	if onlyLower.MatchString(key) {
		return true
	}
	// Only uppercase letters
	if onlyUpper.MatchString(key) {
		return true
	}
	// Sequential patterns
	if sequential.MatchString(key) {
		return true
	}
	return false
}

// FromData will find and optionally verify JumpCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// match[0] is the full match (jca_ + key), match[1] is the captured group (key only)
		fullMatch := strings.TrimSpace(match[0])
		keyPart := strings.TrimSpace(match[1])

		// Filter out obvious false positives
		if isLikelyFalsePositive(keyPart) {
			continue
		}

		// Entropy check - real keys have good randomness
		if detectors.StringShannonEntropy(keyPart) < 3.0 {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Jumpcloud,
			Raw:          []byte(fullMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://console.jumpcloud.com/api/v2/systemgroups", nil)
			if err != nil {
				continue
			}
			req.Header.Add("x-api-key", fullMatch)

			res, err := client.Do(req)
			if err == nil {
				defer func() { _ = res.Body.Close() }()
				switch res.StatusCode {
				case http.StatusOK:
					s1.Verified = true
				case http.StatusUnauthorized, http.StatusForbidden:
					// Secret is determinately not verified (nothing to do)
				default:
					err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					s1.SetVerificationError(err, fullMatch)
				}
			} else {
				s1.SetVerificationError(err, fullMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Jumpcloud
}

func (s Scanner) Description() string {
	return "JumpCloud is a cloud-based directory service platform that offers user and device management, single sign-on, and other identity and access management (IAM) features. JumpCloud API keys with the jca_ prefix can be used to access and manage these services."
}
