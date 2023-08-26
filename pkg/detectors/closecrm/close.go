package closecrm

import (
	"bytes"
	"context"
	b64 "encoding/base64"
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
	keyPat = regexp.MustCompile(`\b(api_[a-z0-9A-Z.]{45})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("close")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Close,
			Raw:          resMatch,
		}

		if verify {
			data := append(resMatch, byte(':'))
			sEnc := b64.StdEncoding.EncodeToString(data)
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.close.com/api/v1/me/", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", "Basic "+sEnc)
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Close
}
