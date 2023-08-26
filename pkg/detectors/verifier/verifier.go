package verifier

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

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"verifier"}) + `\b([a-z0-9]{96})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"verifier"}) + `\b([a-zA-Z-0-9]{5,16}@[-a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("verifier")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := emailPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			userPatMatch := bytes.TrimSpace(idMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Verifier,
				Raw:          resMatch,
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://verifier.meetchopra.com/verify/%s?token=%s", string(userPatMatch), string(resMatch)), nil)
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Verifier
}
