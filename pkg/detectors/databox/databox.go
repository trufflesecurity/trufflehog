package databox

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"databox"}) + common.BuildRegex(common.RegexPattern, "", 21))
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("databox")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Databox,
			Raw:          resMatch,
		}
		if verify {
			data := fmt.Sprintf("%s:", string(resMatch))
			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			payload := bytes.NewBuffer([]byte(`{
				"data":[
				  {
					"$sales": 420,
					"$visitors": 123000
				  }
				]
			  }`))

			req, err := http.NewRequestWithContext(ctx, "POST", "https://push.databox.com", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Accept", "application/vnd.databox.v2+json")
			req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	return detectorspb.DetectorType_Databox
}
