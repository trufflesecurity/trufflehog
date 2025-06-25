package cloudelements

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudelements"}) + `\b([a-zA-Z0-9]{43})\b`)
	orgPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudelements"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloudelements"}
}

// FromData will find and optionally verify CloudElements secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	orgMatches := orgPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, orgMatch := range orgMatches {

			resOrgMatch := strings.TrimSpace(orgMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CloudElements,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resOrgMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://staging.cloud-elements.com/elements/api-v2/accounts", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("User %s, Organization %s", resMatch, resOrgMatch))
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
	return detectorspb.DetectorType_CloudElements
}

func (s Scanner) Description() string {
	return "CloudElements is an API integration platform that enables developers to connect their applications with various cloud services. CloudElements credentials can be used to access and manage these integrations."
}
