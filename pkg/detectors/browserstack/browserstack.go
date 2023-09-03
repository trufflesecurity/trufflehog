package browserstack

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

	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"https://", "http://", "hub-cloud.browserstack.com", "accessKey", "\"access_Key\":", "ACCESS_KEY", "key", "browserstackKey", "BS_AUTHKEY", "BROWSERSTACK_ACCESS_KEY"}) + `\b([0-9a-zA-Z]{20})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"https://", "http://", "hub-cloud.browserstack.com", "userName", "\"username\":", "USER_NAME", "user", "browserstackUser", "BS_USERNAME", "BROWSERSTACK_USERNAME"}) + `\b([a-zA-Z\d]{3,18}[._-]+[a-zA-Z\d]{6})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("browserstack")}
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

			resUserMatch := bytes.TrimSpace(userMatch[1])

			result := detectors.Result{
				DetectorType: detectorspb.DetectorType_BrowserStack,
				Raw:          resMatch,
				RawV2:        append(resMatch, resUserMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://www.browserstack.com/automate/plan.json", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.SetBasicAuth(string(resUserMatch), string(resMatch))
				res, err := client.Do(req)
				if err != nil {
					continue
				}

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					result.Verified = true
				} else if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}
			}
			results = append(results, result)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BrowserStack
}
