package checkvist

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"checkvist"}) + `\b([0-9a-zA-Z]{14})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"checkvist"}) + `\b([\w\.-]+@[\w-]+\.[\w\.-]{2,5})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("checkvist")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			resEmailMatch := bytes.TrimSpace(emailMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Checkvist,
				Raw:          resMatch,
				RawV2:        append(resMatch, resEmailMatch...),
			}

			if verify {
				payload := url.Values{}
				payload.Add("username", string(resEmailMatch))
				payload.Add("remote_key", string(resMatch))

				req, err := http.NewRequest("GET", "https://checkvist.com/auth/login.json?version=2", strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
	return detectorspb.DetectorType_Checkvist
}
