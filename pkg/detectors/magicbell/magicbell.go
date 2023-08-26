package magicbell

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

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"magicbell"}) + `\b([a-zA-Z-0-9]{40})\b`)
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("magicbell")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	apiKeyMatches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range apiKeyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		apiKeyRes := bytes.TrimSpace(keyMatch[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			emailRes := bytes.TrimSpace(emailMatch[1])

			if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MagicBell,
				Raw:          apiKeyRes,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.magicbell.com/notification_preferences", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-MAGICBELL-API-KEY", string(apiKeyRes))
				req.Header.Add("X-MAGICBELL-USER-EMAIL", string(emailRes))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_MagicBell
}
