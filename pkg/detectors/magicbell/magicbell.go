package magicbell

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"magicbell"}) + `\b([a-zA-Z-0-9]{40})\b`)
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"magicbell"}
}

// FromData will find and optionally verify MagicBell secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	emailMatches := emailPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range apiKeyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		apiKeyRes := strings.TrimSpace(keyMatch[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			emailRes := strings.TrimSpace(emailMatch[1])

			if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) { // wait- (apiKeyRes, email) might be false positive does not mean (apiKeyRes, another_email) is ?
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MagicBell,
				Raw:          []byte(apiKeyRes),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.magicbell.com/notification_preferences", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-MAGICBELL-API-KEY", apiKeyRes)
				req.Header.Add("X-MAGICBELL-USER-EMAIL", emailRes)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MagicBell
}
