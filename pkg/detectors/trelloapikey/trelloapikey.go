package trelloapikey

import (
	"context"
	// "log"
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
	client   = common.SaneHttpClient()
	tokenPat = regexp.MustCompile(`\b([a-zA-Z-0-9]{64})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"trello"}) + `\b([a-zA-Z-0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"trello"}
}

// FromData will find and optionally verify TrelloApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	tokenMatches := tokenPat.FindAllStringSubmatch(dataStr, -1)

	for i, match := range matches {
		if i == 0 {
			resMatch := strings.TrimSpace(match[1])
			for _, tokenMatch := range tokenMatches {
				if len(tokenMatch) != 2 {
					continue
				}

				token := strings.TrimSpace(tokenMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrelloApiKey,
					Redacted:     resMatch,
					Raw:          []byte(resMatch),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", "https://api.trello.com/1/members/me?key="+resMatch+"&token="+token, nil)
					if err != nil {
						continue
					}
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}
				results = append(results, s1)

			}
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TrelloApiKey
}
