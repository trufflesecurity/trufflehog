package slackwebhook

import (
	"context"
	"io/ioutil"

	// "log"
	"regexp"
	"strings"

	"net/http"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	//Make sure that your group is surrounded in boundry characters such as below to reduce false positives
	keyPat = regexp.MustCompile(`(https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,46})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hooks.slack.com"}
}

// FromData will find and optionally verify SlackWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SlackWebhook,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"text": ""}`)
			req, _ := http.NewRequestWithContext(ctx, "POST", resMatch, payload)
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, _ := ioutil.ReadAll(res.Body)
				body := string(bodyBytes)
				if (res.StatusCode >= 200 && res.StatusCode < 300) || (res.StatusCode == 400 && strings.Contains(body, "missing_text")) {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}
