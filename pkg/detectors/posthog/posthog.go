package posthog

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat = regexp.MustCompile(`\b(phx_[a-zA-Z0-9_]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"phx_"}
}

// FromData will find and optionally verify AppPosthog secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PosthogApp,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://app.posthog.com/api/event/?personal_api_key="+resMatch, nil)
			reqEU, errEU := http.NewRequestWithContext(ctx, "GET", "https://eu.posthog.com/api/event/?personal_api_key="+resMatch, nil)

			if err != nil || errEU != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			reqEU.Header.Add("Content-Type", "application/json")

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
					s1.AnalysisInfo = map[string]string{
						"key": resMatch,
					}
				} else if res.StatusCode == 401 {
					// Try EU Endpoint only if other one fails.
					res, err := client.Do(reqEU)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.AnalysisInfo = map[string]string{
								"key": resMatch,
							}
						}
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PosthogApp
}

func (s Scanner) Description() string {
	return "PostHog is an open-source product analytics platform. The phx_ keys are used to authenticate and track events in PostHog."
}
