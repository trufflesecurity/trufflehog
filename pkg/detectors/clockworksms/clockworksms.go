package clockworksms

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

	userKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"clockwork", "textanywhere"}) + `\b([0-9]{5})\b`)
	tokenPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"clockwork", "textanywhere"}) + `\b([0-9a-zA-Z]{24})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("clockworksms"), []byte("textanywhere")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	userKeyMatches := userKeyPat.FindAllSubmatch(data, -1)
	tokenMatches := tokenPat.FindAllSubmatch(data, -1)

	for _, match := range userKeyMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, tokenMatch := range tokenMatches {
			if len(tokenMatch) != 2 {
				continue
			}
			tokenRes := bytes.TrimSpace(tokenMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ClockworkSMS,
				Raw:          resMatch,
				RawV2:        append(resMatch, tokenRes...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.textanywhere.com/API/v1.0/REST/status", nil)
				if err != nil {
					continue
				}
				req.Header.Add("user_key", string(resMatch))
				req.Header.Add("access_token", string(tokenRes))
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
	return detectorspb.DetectorType_ClockworkSMS
}
