package hiveage

import (
	"bytes"
	"context"
	b64 "encoding/base64"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hiveage"}) + `\b([0-9A-Za-z\_\-]{20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("hiveage")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Hiveage,
			Raw:          resMatch,
		}

		if verify {
			encData := []byte(fmt.Sprintf("%s:", string(resMatch)))
			encoded := b64.StdEncoding.EncodeToString(encData)
			req, err := http.NewRequestWithContext(ctx, "GET", "https://mltb8350.hiveage.com/api/network", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))
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
	return detectorspb.DetectorType_Hiveage
}
