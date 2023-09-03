package sendgrid

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sendgrid"}) + `(SG\.[\w\-_]{20,24}\.[\w\-_]{39,50})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("SG.")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_SendGrid,
			Raw:          resMatch,
		}

		if verify {
			baseURL := []byte("https://api.sendgrid.com/v3/templates")

			req, err := http.NewRequestWithContext(ctx, "GET", string(baseURL), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()

				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					s.Verified = true
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SendGrid
}
