package trufflehogenterprise

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat      = regexp.MustCompile(`\bthog-key-[0-9a-f]{16}\b`)
	secretPat   = regexp.MustCompile(`\bthog-secret-[0-9a-f]{32}\b`)
	hostnamePat = regexp.MustCompile(`\b[a-z]+-[a-z]+-[a-z]+\.[a-z][0-9]\.[a-z]+\.trufflehog\.org\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"thog"}
}

// FromData will find and optionally verify TruffleHog Enterprise secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	hostnameMatches := hostnamePat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 1 {
			continue
		}
		resKeyMatch := strings.TrimSpace(keyMatch[0])
		for _, secretMatch := range secretMatches {

			if len(secretMatch) != 1 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[0])

			for _, hostnameMatch := range hostnameMatches {
				if len(hostnameMatch) != 1 {
					continue
				}

				resHostnameMatch := strings.TrimSpace(hostnameMatch[0])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrufflehogEnterprise,
					Raw:          []byte(resKeyMatch),
				}

				if verify {
					endpoint := fmt.Sprintf("https://%s/api/v1/sources", resHostnameMatch)
					req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
					if err != nil {
						continue
					}

					req.Header.Add("Accept", "application/vnd.trufflehogenterprise+json; version=3")
					req.Header.Add("X-Thog-Secret", resSecretMatch)
					req.Header.Add("X-Thog-Key", resKeyMatch)

					res, err := client.Do(req)
					if err == nil {
						verifiedBodyResponse, err := common.ResponseContainsSubstring(res.Body, "data")
						if err != nil {
							return nil, err
						}

						defer res.Body.Close()

						if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_TrufflehogEnterprise
}
