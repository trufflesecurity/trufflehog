package tickettailor

import (
	"bytes"
	"context"
	"encoding/base64"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"tickettailor"}) + `\b(sk[a-fA-Z0-9_]{45})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("tickettailor")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Tickettailor,
			Raw:          resMatch,
		}

		if verify {
			data := fmt.Sprintf("%s:", string(resMatch))
			sEnc := base64.StdEncoding.EncodeToString([]byte(data))
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.tickettailor.com/v1/orders", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.tickettailor+json; version=3")
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
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Tickettailor
}
