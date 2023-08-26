package tru

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

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"tru"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
	secrePat = regexp.MustCompile(detectors.PrefixRegex([]string{"tru"}) + `\b([0-9a-zA-Z.-_]{26})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("tru")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secrePat.FindAllSubmatch(data, -1)

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
				DetectorType: detectorspb.DetectorType_Tru,
				Raw:          resMatch,
				RawV2:        append(resMatch, resSecret...),
			}

			if verify {
				data := append(resMatch, byte(':'))
				data = append(data, resSecret...)
				baseToken := b64.StdEncoding.EncodeToString(data)
				payload := bytes.NewBuffer([]byte("grant_type=client_credentials"))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://eu.api.tru.id/oauth2/v1/token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", baseToken))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(bytes.TrimSpace(resMatch), detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Tru
}
