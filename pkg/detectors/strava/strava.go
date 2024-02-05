package strava

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9]{5})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9a-z]{40})\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9a-z]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"strava"}
}

// FromData will find and optionally verify Strava secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}
		resId := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecret := strings.TrimSpace(secretMatch[1])

			for _, keyMatch := range keyMatches {
				if len(keyMatch) != 2 {
					continue
				}
				resKey := strings.TrimSpace(keyMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Strava,
					Raw:          []byte(resId),
					RawV2:        []byte(resId + resSecret),
				}

				if verify {
					payload := strings.NewReader("grant_type=refresh_token&client_id=" + resId + "&client_secret=" + resSecret + "&refresh_token=" + resKey)

					req, err := http.NewRequestWithContext(ctx, "POST", "https://www.strava.com/oauth/token", payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resId, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Strava
}
