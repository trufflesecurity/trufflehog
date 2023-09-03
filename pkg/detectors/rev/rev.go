package rev

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

	userKeyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"rev"}) + `\b([0-9a-zA-Z\/\+]{27}\=[ \r\n]{1})`)
	clientKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"rev"}) + `\b([0-9a-zA-Z\-]{27}[ \r\n]{1})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("rev")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	userMatches := userKeyPat.FindAllSubmatch(data, -1)
	clientMatches := clientKeyPat.FindAllSubmatch(data, -1)

	for _, userMatch := range userMatches {
		if len(userMatch) != 2 {
			continue
		}
		resUserMatch := bytes.TrimSpace(userMatch[1])

		for _, clientMatch := range clientMatches {
			if len(clientMatch) != 2 {
				continue
			}
			resClientMatch := bytes.TrimSpace(clientMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Rev,
				Raw:          resUserMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://www.rev.com/api/v1/orders", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Rev %s:%s", string(resClientMatch), string(resUserMatch)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resUserMatch, detectors.DefaultFalsePositives, true) {
							continue
						}

						if detectors.IsKnownFalsePositive(resClientMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Rev
}
