package hypertrack

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Keeping the regexp patterns unchanged
	accPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hypertrack"}) + `\b([0-9a-zA-Z\_\-]{27})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hypertrack"}) + `\b([0-9a-zA-Z\_\-]{54})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("hypertrack")}
}

// FromData will find and optionally verify Hypertrack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	accMatches := accPat.FindAllSubmatch(data, -1)
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, accMatch := range accMatches {
		if len(accMatch) != 2 {
			continue
		}
		resAccMatch := bytes.TrimSpace(accMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hypertrack,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://v3.api.hypertrack.com/trips/", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(string(resAccMatch), string(resMatch))
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
						if detectors.IsKnownFalsePositive(resAccMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Hypertrack
}
