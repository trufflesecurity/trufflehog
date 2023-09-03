package paypaloauth

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	idPat  = regexp.MustCompile(`\b([A-Za-z0-9_\.]{7}-[A-Za-z0-9_\.]{72})\b`)
	keyPat = regexp.MustCompile(`\b([A-Za-z0-9_\.]{69}-[A-Za-z0-9_\.]{10})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("paypal")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idmatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, idMatch := range idmatches {
			if len(idMatch) != 2 {
				continue
			}
			residMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PaypalOauth,
				Raw:          resMatch,
			}

			if verify {
				dataAuth := append(residMatch, ':')
				dataAuth = append(dataAuth, resMatch...)
				encoded := b64.StdEncoding.EncodeToString(dataAuth)
				payload := bytes.NewBuffer([]byte("grant_type=client_credentials"))

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api-m.sandbox.paypal.com/v1/oauth2/token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/json")
				req.Header.Add("Accept-Language", "en_US")
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PaypalOauth
}
