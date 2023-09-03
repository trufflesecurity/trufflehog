package getemails

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"getemails"}) + `\b([a-z0-9-]{26})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"getemails"}) + `\b([a-z0-9-]{18})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("getemails")}
}

// FromData will find and optionally verify GetEmails secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	keyMatches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		resKeyMatch := bytes.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GetEmails,
				Raw:          resKeyMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.getemails.com/api/v1/contacts", nil)
				if err != nil {
					continue
				}
				req.Header.Add("api-key", string(resKeyMatch))
				req.Header.Add("api-id", string(resIdMatch))

				res, err := client.Do(req)

				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resKeyMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_GetEmails
}
