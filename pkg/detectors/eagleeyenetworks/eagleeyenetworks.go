package eagleeyenetworks

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"eagleeyenetworks"}) + `\b([a-zA-Z0-9]{15})\b`)
	email  = regexp.MustCompile(detectors.PrefixRegex([]string{"eagleeyenetworks"}) + `\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("eagleeyenetworks")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := email.FindAllSubmatch(data, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}

			resEmailPatMatch := bytes.TrimSpace(emailMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_EagleEyeNetworks,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewReader([]byte(fmt.Sprintf(`{"username": "%s", "password": "%s"}`, string(resEmailPatMatch), string(resMatch))))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://login.eagleeyenetworks.com/g/aaa/authenticate", payload)
				if err != nil {
					continue
				}
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
					}
				}
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EagleEyeNetworks
}
