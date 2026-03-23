package cloudflareapitoken

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Legacy format: 40-char alphanumeric, requires "cloudflare" keyword nearby.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudflare"}) + `\b([A-Za-z0-9_-]{40})\b`)
	// 2026+ formats: cfut_ (user token) and cfat_ (account token), self-identifying.
	keyV2Pat = regexp.MustCompile(`\b(cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`)
	// Cloudflare account ID pattern for cfat_ token verification.
	accountIDPat = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloudflare", "cfut_", "cfat_"}
}

// FromData will find and optionally verify CloudflareApiToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	matches = append(matches, keyV2Pat.FindAllStringSubmatch(dataStr, -1)...)

	// Extract account IDs from surrounding data for cfat_ verification.
	uniqueAccountIDs := make(map[string]struct{})
	for _, match := range accountIDPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccountIDs[match[1]] = struct{}{}
	}

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		if verify {
			if strings.HasPrefix(resMatch, "cfat_") {
				// Account tokens require per-account verification.
				for accountID := range uniqueAccountIDs {
					s1 := detectors.Result{
						DetectorType: detectorspb.DetectorType_CloudflareApiToken,
						Raw:          []byte(resMatch),
						RawV2:        []byte(resMatch + accountID),
					}
					verified := verifyAccountToken(ctx, resMatch, accountID)
					s1.Verified = verified
					results = append(results, s1)
				}
				if len(uniqueAccountIDs) == 0 {
					// No account ID found; still report the token unverified.
					results = append(results, detectors.Result{
						DetectorType: detectorspb.DetectorType_CloudflareApiToken,
						Raw:          []byte(resMatch),
					})
				}
			} else {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_CloudflareApiToken,
					Raw:          []byte(resMatch),
				}
				s1.Verified = verifyUserToken(ctx, resMatch)
				results = append(results, s1)
			}
		} else {
			results = append(results, detectors.Result{
				DetectorType: detectorspb.DetectorType_CloudflareApiToken,
				Raw:          []byte(resMatch),
			})
		}
	}

	return results, nil
}

func verifyUserToken(ctx context.Context, token string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	if err != nil {
		return false
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}

func verifyAccountToken(ctx context.Context, token, accountID string) bool {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/tokens/verify", accountID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CloudflareApiToken
}

func (s Scanner) Description() string {
	return "Cloudflare is a web infrastructure and website security company, providing content delivery network services, DDoS mitigation, Internet security, and distributed domain name server services. Cloudflare API tokens can be used to manage and interact with Cloudflare services."
}
