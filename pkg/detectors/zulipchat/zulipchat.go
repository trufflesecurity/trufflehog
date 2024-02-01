package zulipchat

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
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
	keyPat    = regexp.MustCompile(common.BuildRegex(common.AlphaNumPattern, "", 32))
	idPat     = regexp.MustCompile(`\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b`)
	domainPat = regexp.MustCompile(`\b([a-z0-9-]+\.zulip(?:(?:chat)?\.com|\.org))\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zulip"}
}

// FromData will find and optionally verify ZulipChat secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			// getting the last word of the string
			resIdMatch := strings.TrimSpace(idMatch[1])

			for _, domainMatch := range domainMatches {
				if len(domainMatch) != 2 {
					continue
				}

				resDomainMatch := strings.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZulipChat,
					Raw:          []byte(resMatch),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", resMatch, resIdMatch, resDomainMatch)),
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v1/users", resDomainMatch), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.SetBasicAuth(resIdMatch, resMatch)
					res, err := client.Do(req)

					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else if res.StatusCode == 401 {
							// This secret is determinately not verified, nothing to do here
						} else {
							s1.SetVerificationError(fmt.Errorf("unexpected HTTP response status %d", res.StatusCode), resMatch)
						}
					} else {
						s1.SetVerificationError(err, resMatch)
					}
				}
				if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZulipChat
}
