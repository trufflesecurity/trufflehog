package facebookoauth

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

	apiIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"facebook"}) + `\b([0-9]{15,18})\b`)
	apiSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"facebook"}) + `\b([A-Za-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("facebook")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	apiIdMatches := apiIdPat.FindAllSubmatch(data, -1)
	apiSecretMatches := apiSecretPat.FindAllSubmatch(data, -1)

	for _, apiIdMatch := range apiIdMatches {
		if len(apiIdMatch) != 2 {
			continue
		}
		apiIdRes := bytes.TrimSpace(apiIdMatch[1])

		for _, apiSecretMatch := range apiSecretMatches {
			if len(apiSecretMatch) != 2 {
				continue
			}
			apiSecretRes := bytes.TrimSpace(apiSecretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_FacebookOAuth,
				Redacted:     string(apiIdRes),
				Raw:          apiSecretRes,
				RawV2:        append(apiIdRes, apiSecretRes...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://graph.facebook.com/%s?fields=roles&access_token=%s|%s", apiIdRes, apiIdRes, apiSecretRes), nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(apiIdRes, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_FacebookOAuth
}
