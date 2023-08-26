package textmagic

import (
	"bytes"
	"context"
	b64 "encoding/base64"
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

	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"textmagic"}) + `\b([0-9A-Za-z]{30})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"textmagic"}) + `\b([0-9A-Za-z]{1,25})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("textmagic")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	userMatches := userPat.FindAllSubmatch(data, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, userMatch := range userMatches {
			if len(userMatch) != 2 {
				continue
			}
			resUser := bytes.TrimSpace(userMatch[1])

			rawV2 := append(resMatch, resUser...)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Textmagic,
				Raw:          resMatch,
				RawV2:        rawV2,
			}

			if verify {
				data := append(resUser, resMatch...)
				sEnc := b64.StdEncoding.EncodeToString(data)
				req, err := http.NewRequestWithContext(ctx, "GET", "https://rest.textmagic.com/api/v2/user", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	return detectorspb.DetectorType_Textmagic
}
