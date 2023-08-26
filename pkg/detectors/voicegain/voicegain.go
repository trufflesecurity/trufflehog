package voicegain

import (
	"bytes"
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"voicegain"}) +
		`\b(ey[0-9a-zA-Z_-]{34}.ey[0-9a-zA-Z_-]{108}.[0-9a-zA-Z_-]{43})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("voicegain")}
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
			DetectorType: detectorspb.DetectorType_Voicegain,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.voicegain.ai/v1/sa/config", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
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
	return detectorspb.DetectorType_Voicegain
}
