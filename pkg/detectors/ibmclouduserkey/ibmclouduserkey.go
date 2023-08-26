package ibmclouduserkey

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ibm"}) + `\b([A-Za-z0-9_-]{44})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("ibm")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_IbmCloudUserKey,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBuffer([]byte("apikey=" + string(resMatch) + "&grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey"))
			req, err := http.NewRequestWithContext(ctx, "POST", "https://iam.cloud.ibm.com/identity/token", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Add("Authorization", "Basic Yng6Yng=")
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
	return detectorspb.DetectorType_IbmCloudUserKey
}
