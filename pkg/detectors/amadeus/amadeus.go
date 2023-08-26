package amadeus

import (
	"bytes"
	"context"
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
	client    = common.SaneHttpClient()
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"amadeus"}) + `\b([0-9A-Za-z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"amadeus"}) + `\b([0-9A-Za-z]{16})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("amadeus")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecret := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Amadeus,
				Raw:          resMatch,
				RawV2:        append(resMatch, resSecret...),
			}

			if verify {
				payload := bytes.NewReader(append(append([]byte("grant_type=client_credentials&client_id="), resMatch...), append([]byte("&client_secret="), resSecret...)...))

				req, err := http.NewRequestWithContext(ctx, "POST", "https://test.api.amadeus.com/v1/security/oauth2/token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					if res.StatusCode >= 200 && res.StatusCode < 300 && bytes.Contains(bodyBytes, []byte("access_token")) {
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
	return detectorspb.DetectorType_Amadeus
}
