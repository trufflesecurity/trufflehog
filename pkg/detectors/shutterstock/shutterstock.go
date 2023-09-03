package shutterstock

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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"shutterstock"}) + `\b([0-9a-zA-Z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shutterstock"}) + `\b([0-9a-zA-Z]{16})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("shutterstock")}
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
			resSecretMatch := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Shutterstock,
				Raw:          resSecretMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.shutterstock.com/v2/images/search", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/json")
				req.SetBasicAuth(string(resMatch), string(resSecretMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}

						if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Shutterstock
}
