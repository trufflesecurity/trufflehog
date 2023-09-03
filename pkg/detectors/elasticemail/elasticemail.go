package elasticemail

import (
	"bytes"
	"context"
	"encoding/json"
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
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"elastic"}) + `\b([A-Za-z0-9_-]{96})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("elasticemail")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ElasticEmail,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.elasticemail.com/v2/account/profileoverview?apikey="+string(resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				data, readErr := io.ReadAll(res.Body)
				res.Body.Close()
				if readErr == nil {
					var ResVar struct {
						Success bool `json:"success"`
					}
					if err := json.Unmarshal(data, &ResVar); err == nil {
						if ResVar.Success {
							s1.Verified = true
						}
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ElasticEmail
}
