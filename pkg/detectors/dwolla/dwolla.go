package dwolla

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

	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"dwolla"}) + `\b([a-zA-Z-0-9]{50})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dwolla"}) + `\b([a-zA-Z-0-9]{50})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("dwolla")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := idPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}

		idMatch := bytes.TrimSpace(match[1])

		for _, secret := range secretMatches {
			if len(secret) != 2 {
				continue
			}

			secretMatch := bytes.TrimSpace(secret[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dwolla,
				Raw:          idMatch,
				RawV2:        append(idMatch, secretMatch...),
			}

			if verify {
				data := append(idMatch, ':')
				data = append(data, secretMatch...)
				encoded := b64.StdEncoding.EncodeToString(data)
				payload := bytes.NewBufferString("grant_type=client_credentials")

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api-sandbox.dwolla.com/token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(idMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Dwolla
}
