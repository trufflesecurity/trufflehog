package kanban

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kanban"}) + `\b([0-9A-Z]{12})\b`)
	urlPat = regexp.MustCompile(`\b([0-9a-z]{1,}\.kanbantool\.com)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("kanban")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	urlMatches := urlPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			if len(urlMatch) != 2 {
				continue
			}
			resURL := bytes.TrimSpace(urlMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Kanban,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v3/users/current.json", resURL), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.kanban+json; version=3")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Kanban
}
