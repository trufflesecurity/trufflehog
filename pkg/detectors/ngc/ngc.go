package ngc

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat1 = regexp.MustCompile(`\b([[:alnum:]]{84})\b`)
	keyPat2 = regexp.MustCompile(`\b([[:alnum:]]{26}:[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("ngc")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat1.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := match[1]

		decode, _ := base64.StdEncoding.DecodeString(string(resMatch))

		containsKey := keyPat2.Match(decode)
		if containsKey {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_NGC,
				Raw:          resMatch,
			}

			if verify {
				key := []byte("Basic " + string(base64.StdEncoding.EncodeToString(append([]byte("$oauthtoken:"), resMatch...))))
				req, err := http.NewRequestWithContext(ctx, "GET", "https://authn.nvidia.com/token?service=ngc", nil)
				if err != nil {
					continue
				}
				req.Header = http.Header{
					"accept":        {string([]byte("*/*"))},
					"Authorization": {string(key)},
				}
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

	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NGC
}
