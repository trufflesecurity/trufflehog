package cloudflareglobalapikey

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

	apiKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudflare"}) + `([A-Za-z0-9_-]{37})`)

	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("cloudflare")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	apiKeyMatches := apiKeyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, apiKeyMatch := range apiKeyMatches {
		if len(apiKeyMatch) != 2 {
			continue
		}
		apiKeyRes := bytes.TrimSpace(apiKeyMatch[1])

		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			emailRes := bytes.TrimSpace(emailMatch[1])

			if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CloudflareGlobalApiKey,
				Redacted:     string(emailRes),
				Raw:          apiKeyRes,
				RawV2:        append(apiKeyRes, emailRes...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/user", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Auth-Email", string(emailRes))
				req.Header.Add("X-Auth-Key", string(apiKeyRes))
				req.Header.Add("Content-Type", "application/json")

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CloudflareGlobalApiKey
}
