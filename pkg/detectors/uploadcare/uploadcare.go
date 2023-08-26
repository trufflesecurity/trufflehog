package uploadcare

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

	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"uploadcare"}) + `\b([a-z0-9]{20})\b`)
	publicKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"uploadcare"}) + `\b([a-z0-9]{20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("uploadcare")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	publicMatches := publicKeyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, publicMatch := range publicMatches {
			if len(publicMatch) != 2 {
				continue
			}
			publicKeyMatch := bytes.TrimSpace(publicMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_UploadCare,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequest("GET", "https://api.uploadcare.com/files/", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/vnd.uploadcare-v0.5+json")
				req.Header.Add("Authorization", fmt.Sprintf("Uploadcare.Simple %s:%s", string(publicKeyMatch), string(resMatch)))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_UploadCare
}
