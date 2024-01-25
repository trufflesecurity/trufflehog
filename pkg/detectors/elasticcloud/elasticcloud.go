package elasticcloud

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
	keyPat    = regexp.MustCompile(`([A-Za-z0-9+/=]{60,100})`)
	domainPat = regexp.MustCompile(`([a-zA-Z0-9-.]+\.elastic-cloud\.com\:[0-9]{2,5})|([a-zA-Z0-9-.]+\.cloud\.es\.io\:[0-9]{2,5})|([a-zA-Z0-9-.]+\.ip\.es\.io\:[0-9]{2,5})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloud.es.io", "elastic-cloud.com", "ip.es.io"}
}

// FromData will find and optionally verify Elasticcloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllString(dataStr, -1)
	domainMatches := domainPat.FindAllString(dataStr, -1)

	fmt.Println(keyMatches, domainMatches)

	for _, match := range keyMatches {
		key := strings.TrimSpace(match)

		for _, domainMatch := range domainMatches {
			domainRes := strings.TrimSpace(domainMatch)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ElasticCloud,
				Raw:          []byte(key + domainRes),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes, nil)
				if err != nil {
					continue
				}
				port := strings.Split(domainRes, ":")[1]
				if port == "443" || port == "80" {
					//Handle REST API Auth
					req.Header.Add("Authorization", "Basic "+key)
				} else {
					//Handle Elastic Search Auth
					req.Header.Add("Authorization", "ApiKey "+key)
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, key)
					}
				} else {
					s1.SetVerificationError(err, key)
				}
			}

			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ElasticCloud
}
