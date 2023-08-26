package slackwebhook

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("hooks.slack.com")}
}

// FromData will find and optionally verify SlackWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SlackWebhook,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBuffer([]byte(`{"text": ""}`))
			req, err := http.NewRequestWithContext(ctx, "POST", string(resMatch), payload)
			if err != nil {
				continue
			}

			req.Header.Add("Content-Type", "application/json")

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()

				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				if (res.StatusCode >= 200 && res.StatusCode < 300) || (res.StatusCode == 400 &&
					(bytes.Contains(bodyBytes, []byte("no_text")) || bytes.Contains(bodyBytes, []byte("missing_text")))) {

					s1.Verified = true
				}
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SlackWebhook
}
