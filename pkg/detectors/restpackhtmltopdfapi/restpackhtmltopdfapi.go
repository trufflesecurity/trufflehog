package restpackhtmltopdfapi

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"restpack"}) + `\b([0-9A-Za-z]{48})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("restpack")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result

	matches := keyPat.FindAllSubmatch(data, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_RestpackHtmlToPdfAPI,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://restpack.io/api/html2pdf/usage", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("X-Access-Token", string(resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RestpackHtmlToPdfAPI
}
