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

type KeyPatScanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the KeyPatScanner satisfies the interface at compile time.
var _ detectors.Detector = (*KeyPatScanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "token", "pat", "vsce"}) + `[:\s]?\s*["']?([0-9a-z]{52})["']?\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s KeyPatScanner) Keywords() []string {
	return []string{"azure", "token", "pat", "vsce"}
}

// FromData will find and optionally verify AzureDevopsPersonalAccessToken secrets in a given set of bytes.
func (s KeyPatScanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AzureDevopsPersonalAccessToken,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://marketplace.visualstudio.com/_apis/securityroles", nil)
			if err != nil {
				s1.SetVerificationError(err, resMatch)
			} else {
				req.SetBasicAuth("OAuth", resMatch)
				req.Header.Add("Accept", "application/json")
				req.Header.Add("User-Agent", "node-SecurityRoles-api")
				req.Header.Add("X-Tfs-Fedauthredirect", "Suppress")
				req.Header.Add("Connection", "close")

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					fmt.Printf("Debug: HTTP Status Code: %d\n", res.StatusCode)
					if res.StatusCode >= 200 && res.StatusCode < 300 {
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
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s KeyPatScanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureDevopsPersonalAccessToken
}

func (s KeyPatScanner) Description() string {
	return "Azure DevOps is a suite of development tools provided by Microsoft. Personal Access Tokens (PATs) are used to authenticate and authorize access to Azure DevOps services and resources."
}
