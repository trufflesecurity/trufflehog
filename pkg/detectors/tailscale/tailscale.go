package tailscale

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\btskey-[a-z]+-[0-9A-Za-z_]+-[0-9A-Za-z_]+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"tskey-", "tskey-api-", "tskey-oauth-"}
}

// FromData will find and optionally verify Tailscaleapi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[0])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Tailscale,
			Raw:          []byte(resMatch),
		}

		if verify {
			const u = "https://api.tailscale.com/api/v2/secret-scanning/verify"
			vals := url.Values{"key": []string{resMatch}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(vals.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				switch res.StatusCode {
				case http.StatusNoContent:
					s1.Verified = true
				case http.StatusUnauthorized:
					// The secret is determinately not verified (nothing to do)
				default:
					err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					s1.SetVerificationError(err, resMatch)
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Tailscale
}
