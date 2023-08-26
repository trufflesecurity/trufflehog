package trelloapikey

import (
	"bytes"
	"context"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client   = common.SaneHttpClient()
	tokenPat = regexp.MustCompile(`\b([a-zA-Z-0-9]{64})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"trello"}) + `\b([a-zA-Z-0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("trello")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	tokenMatches := tokenPat.FindAllSubmatch(data, -1)

	for i, match := range matches {
		if i == 0 {
			for _, tokenMatch := range tokenMatches {
				if len(tokenMatch) != 2 {
					continue
				}

				token := bytes.TrimSpace(tokenMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrelloApiKey,
					Raw:          match[1],
					Redacted:     string(match[1]),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", "https://api.trello.com/1/members/me?key="+string(match[1])+"&token="+string(token), nil)
					if err != nil {
						continue
					}

					res, err := client.Do(req)
					if err == nil {
						res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(match[1], detectors.DefaultFalsePositives, true) {
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
