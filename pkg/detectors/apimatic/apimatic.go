package apimatic

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

// Ensures Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Ensure your group is surrounded in boundary characters to reduce false positives.
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"apimatic"}) + `\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`)
	passPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apimatic"}) + `\b([a-z0-9-\S]{8,32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("apimatic")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	passMatches := passPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		userPatMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range passMatches {
			if len(idMatch) != 2 {
				continue
			}

			passPatMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_APIMatic,
				Raw:          userPatMatch,
				RawV2:        append(userPatMatch, passPatMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://www.apimatic.io/api/code-generations", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(string(userPatMatch), string(passPatMatch))
				res, err := client.Do(req)

				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(passPatMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_APIMatic
}
