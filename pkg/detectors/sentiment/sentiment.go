package sentiment

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
	client = common.SaneHttpClient()

	tokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sentiment"}) + `\b([a-zA-Z0-9]{20})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"sentiment"}) + `\b([0-9]{17})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sentiment")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	tokenMatches := tokenPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range tokenMatches {
		if len(match) != 2 {
			continue
		}

		tokenMatch := bytes.TrimSpace(match[1])

		for _, secret := range keyMatches {
			if len(secret) != 2 {
				continue
			}

			keyMatch := bytes.TrimSpace(secret[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sentiment,
				Raw:          tokenMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sentimentinvestor.com/v4/parsed?symbol=AAPL&token="+string(tokenMatch)+"&key="+string(keyMatch), nil)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(tokenMatch, detectors.DefaultFalsePositives, true) {
							continue
						}

						if detectors.IsKnownFalsePositive(keyMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Sentiment
}
