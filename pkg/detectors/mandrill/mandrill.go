package mandrill

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mandrill"}) + `\b([A-Za-z0-9_-]{22})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("mandrill")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Mandrill,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewReader([]byte(fmt.Sprintf(`{"key": "%s"}`, string(resMatch))))
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://mandrillapp.com/api/1.0/users/info", payload)
			req.Header.Add("Content-Type", "application/json")
			res, _ := client.Do(req)

			if res.StatusCode >= 200 && res.StatusCode < 300 {
				s1.Verified = true
			} else {
				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mandrill
}
