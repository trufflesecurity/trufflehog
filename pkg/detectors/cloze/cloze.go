package cloze

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"cloze"}) + `\b([0-9a-f]{32})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloze"}) + `\b([\w\.-]+@[\w-]+\.[\w\.-]{2,5})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("cloze")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, emailMatch := range emailMatches {
		if len(emailMatch) != 2 {
			continue
		}
		resEmailMatch := bytes.TrimSpace(emailMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Cloze,
				Raw:          resMatch,
			}

			if verify {
				payload := url.Values{}
				payload.Add("user", string(resEmailMatch))
				payload.Add("api_key", string(resMatch))

				req, err := http.NewRequest("GET", "https://api.cloze.com/v1/profile?"+payload.Encode(), nil)
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
	return detectorspb.DetectorType_Cloze
}
