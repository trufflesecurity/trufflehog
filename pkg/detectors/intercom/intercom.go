package intercom

import (
	"bytes"
	"context"
	"encoding/base64"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"intercom"}) + `\b([a-zA-Z0-9\W\S]{59}\=)`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("intercom")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		dec, err := base64.StdEncoding.DecodeString(string(resMatch))
		if err != nil {
			continue
		}
		if !bytes.HasPrefix(dec, []byte("tok:")) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Intercom,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.intercom.io/contacts?per_page=5", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", "Bearer "+string(resMatch))
			req.Header.Add("Accept", "application/json")

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
	return detectorspb.DetectorType_Intercom
}
