package teamgate

import (
	"context"
	"net/http"
	"regexp"
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
	tokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"teamgate"}) + `\b([a-z0-9]{40})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"teamgate"}) + `\b([a-zA-Z0-9]{80})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"teamgate"}
}

// FromData will find and optionally verify Teamgate secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := tokenPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}

			resKeyMatch := strings.TrimSpace(keyMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Teamgate,
				Raw:          []byte(resMatch),
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.teamgate.com/v4/users", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Auth-Token", resMatch)
				req.Header.Add("X-App-Key", resKeyMatch)

				res, err := client.Do(req)

				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Teamgate
}
