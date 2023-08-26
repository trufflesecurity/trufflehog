package tefter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"tefter"}) + `\b([0-9a-zA-Z]{20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("tefter")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Tefter,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "POST", "https://www.tefter.io/api/bookmarks?url=google.com", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("X-User-Token", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				defer res.Body.Close()

				validResponse := json.Valid(bodyBytes)

				if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
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
	return detectorspb.DetectorType_Tefter
}
