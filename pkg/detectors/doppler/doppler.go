package doppler

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
	personalTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"doppler"}) + `\b(dp\.pt\.[a-zA-Z0-9]{40,44})\b`)
	serviceTokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"doppler"}) + `\b(dp\.st\.(?:[a-z0-9\-_]{2,35}\.)?[a-zA-Z0-9]{40,44})\b`)
	auditTokenPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"doppler"}) + `\b(dp\.audit\.[a-zA-Z0-9]{40,44})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"doppler"}
}

// FromData will find and optionally verify Doppler secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := personalTokenPat.FindAllStringSubmatch(dataStr, -1)
	serviceTokenMatch := serviceTokenPat.FindAllStringSubmatch(dataStr, -1)
	auditTokenMatch := auditTokenPat.FindAllStringSubmatch(dataStr, -1)

	isServiceToken := false

	//Validate which token is detected. Default will be the Personal Token
	if len(serviceTokenMatch) > 0 {
		matches = serviceTokenMatch
		isServiceToken = true
	} else if len(auditTokenMatch) > 0 {
		matches = auditTokenMatch
	}

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Doppler,
			Raw:          []byte(resMatch),
		}

		if verify {
			//This url can both be used by Personal Token and Audit Token
			reqUrl := "https://api.doppler.com/v3/workplace"
			if isServiceToken {
				reqUrl = "https://api.doppler.com/v3/projects"
			}

			req, err := http.NewRequestWithContext(ctx, "GET", reqUrl, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			req.SetBasicAuth(resMatch, "")
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

	return detectors.CleanResults(results), nil
}
