package portainertoken

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"portainertoken"}) + `\b(ptr_[A-Za-z0-9\/_\-+=]{20,60})`)
	endpointPat = regexp.MustCompile(detectors.PrefixRegex([]string{"portainer"}) + `\b(https?:\/\/\S+(:[0-9]{4,5})?)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"portainertoken"}
}

// FromData will find and optionally verify Portainertoken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	endpointMatches := endpointPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, endpointMatch := range endpointMatches {
			resEndpointMatch := strings.TrimSpace(endpointMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PortainerToken,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resEndpointMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				req, err := http.NewRequestWithContext(ctx, "GET", resEndpointMatch + "/api/stacks", nil)
				if err != nil {
					continue
				}

				req.Header.Add("X-API-Key", resMatch)

				res, err := client.Do(req)
				
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified (nothing to do)
					} else {
						s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					}
				} else {
					s1.VerificationError = err
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}

			if len(endpointMatches) > 0 {
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PortainerToken
}
