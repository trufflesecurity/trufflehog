package signalwire

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"signalwire"}) + `\b([0-9A-Za-z]{50})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"signalwire"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
	urlPat = regexp.MustCompile(`\b([0-9a-z-]{3,64}\.signalwire\.com)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("signalwire")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)
	urlMatches := urlPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resID := bytes.TrimSpace(idMatch[1])

			for _, urlMatch := range urlMatches {
				if len(urlMatch) != 2 {
					continue
				}
				resURL := bytes.TrimSpace(urlMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Signalwire,
					Raw:          resMatch,
				}

				if verify {
					data := fmt.Sprintf("%s:%s", string(resID), string(resMatch))
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/laml/2010-04-01/Accounts", string(resURL)), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
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
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Signalwire
}
