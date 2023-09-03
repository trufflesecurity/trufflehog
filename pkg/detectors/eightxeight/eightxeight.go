package eightxeight

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"8x8"}) + `\b([a-zA-Z0-9]{43})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"8x8"}) + `\b([a-zA-Z0-9_]{18,30})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("8x8")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EightxEight,
				Raw:          resMatch,
				RawV2:        append(resMatch, resIdMatch...),
			}

			if verify {
				client.Timeout = 10 * time.Second
				payload := strings.NewReader(`{"source":"abcde","destination":"+6512345678","text":"Hello World!","encoding":"AUTO"}`)
				req, err := http.NewRequest("POST", fmt.Sprintf("https://sms.8x8.com/api/v1/subaccounts/%s/messages", string(resIdMatch)), payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
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
	return detectorspb.DetectorType_EightxEight
}
