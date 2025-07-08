package sonarcloud

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"io"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sonar"}) + `(?:^|[^@])\b([0-9a-z]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sonar"}
}

// FromData will find and optionally verify SonarCloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SonarCloud,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://"+resMatch+"@sonarcloud.io/api/authentication/validate", nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				bodyString := string(bodyBytes)
				validResponse := strings.Contains(bodyString, `"valid":true`)

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					if validResponse {
						s1.Verified = true
					}
				}
			}

		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SonarCloud
}

func (s Scanner) Description() string {
	return "SonarCloud is a cloud-based code quality and security service. SonarCloud tokens can be used to access project analysis and quality reports."
}
