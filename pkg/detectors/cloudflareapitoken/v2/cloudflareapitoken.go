package cloudflareapitoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/cloudflareapitoken/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	v1.Scanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	client = common.SaneHttpClient()

	// 2026+ formats: cfut_ (user token) and cfat_ (account token), self-identifying.
	keyV2Pat = regexp.MustCompile(`\b(cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`)
	// Cloudflare account ID pattern for cfat_ token verification.
	accountIDPat = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cfut_", "cfat_"}
}

// FromData will find and optionally verify CloudflareApiToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyV2Pat.FindAllStringSubmatch(dataStr, -1)

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
						DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
						Raw:          []byte(resMatch),
						RawV2:        []byte(resMatch + accountID),
					}
					s1.Verified = verifyAccountToken(ctx, resMatch, accountID)
					results = append(results, s1)
				}
				if len(uniqueAccountIDs) == 0 {
					// No account ID found; still report the token unverified.
					results = append(results, detectors.Result{
						DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
						Raw:          []byte(resMatch),
					})
				}
			} else {
				// cfut_ tokens use the user token verification endpoint.
				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
					Raw:          []byte(resMatch),
				}
				s1.Verified = v1.VerifyUserToken(ctx, client, resMatch)
				results = append(results, s1)
			}
		} else {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
				Raw:          []byte(resMatch),
			})
		}
	}

	return results, nil
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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CloudflareApiToken
}

func (s Scanner) Description() string {
	return "Cloudflare is a web infrastructure and website security company. Cloudflare API tokens (cfut_/cfat_ prefixed, 2026+ format) can be used to manage and interact with Cloudflare services."
}
