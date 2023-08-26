package swiftype

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"swiftype"}) + `\b([a-zA-z-0-9]{6}\_[a-zA-z-0-9]{6}\-[a-zA-z-0-9]{6})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("swiftype")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Swiftype,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBufferString(`{"auth_token":"` + string(resMatch) + `","q": "gatsby"}`)
			req, err := http.NewRequestWithContext(ctx, "GET", "https://search-api.swiftype.com/api/v1/engines/bookstore/document_types/books/search.json", payload)
			if err != nil {
				continue
			}
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
	return detectorspb.DetectorType_Swiftype
}
