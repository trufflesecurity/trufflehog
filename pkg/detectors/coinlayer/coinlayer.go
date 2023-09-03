package coinlayer

import (
	"bytes"
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"coinlayer"}) + `\b([0-9a-f]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("coinlayer")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	var results []detectors.Result

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Coinlayer,
			Raw:          resMatch,
		}

		if verify {
			url := fmt.Sprintf("https://api.coinlayer.com/api/live?access_key=%s", string(resMatch))
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				v1 := []byte(`"success": true`)
				v2 := []byte(`"info":"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."`)

				bodyBytes, err := io.ReadAll(resp.Body)
				if err != nil || (bytes.Contains(bodyBytes, v1) || bytes.Contains(bodyBytes, v2)) {
					s1.Verified = true
				}
			}

			if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Coinlayer
}
