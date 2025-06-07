package azuredevopspersonalaccesstoken

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
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([0-9a-z]{52})\b`)
	orgPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([0-9a-zA-Z][0-9a-zA-Z-]{5,48}[0-9a-zA-Z])\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure"}
}

// FromData will find and optionally verify AzureDevopsPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	orgMatches := orgPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, orgMatch := range orgMatches {
			resOrgMatch := strings.TrimSpace(orgMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureDevopsPersonalAccessToken,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resOrgMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				req, err := http.NewRequestWithContext(ctx, "GET", "https://dev.azure.com/"+resOrgMatch+"/_apis/projects", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth("", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					hasVerifiedRes, _ := common.ResponseContainsSubstring(res.Body, "lastUpdateTime")
					if res.StatusCode >= 200 && res.StatusCode < 300 && hasVerifiedRes {
						s1.Verified = true
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureDevopsPersonalAccessToken
}

func (s Scanner) Description() string {
	return "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) are used to authenticate and authorize access to Azure DevOps services and resources."
}
