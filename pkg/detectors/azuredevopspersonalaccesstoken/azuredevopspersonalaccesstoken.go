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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure", "token", "pat", "vsce"}) + `[:\s]?\s*["']?([0-9a-z]{52})["']?\b`)
	orgPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([0-9a-zA-Z][0-9a-zA-Z-]{5,48}[0-9a-zA-Z])\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure", "token", "pat", "vsce"}
}

// FromData will find and optionally verify AzureDevopsPersonalAccessToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	orgMatches := orgPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		// First case it matches a pattern without org
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AzureDevopsPersonalAccessToken,
			Raw:          []byte(resMatch),
			RawV2:        []byte(resMatch),
		}
		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, verificationErr := verifyPAT(ctx, client, resMatch)
			s1.Verified = isVerified
			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, resMatch)
			}
		}
		results = append(results, s1)

		// Second case: It matches an org
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
				isVerified, verificationErr := verifyOrgPAT(ctx, client, resMatch, resOrgMatch)
				s1.Verified = isVerified
				if verificationErr != nil {
					s1.SetVerificationError(verificationErr, resMatch)
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

// verifyPAT verifies if the Azure DevOps Personal Access Token is valid
func verifyPAT(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://marketplace.visualstudio.com/_apis/securityroles", nil)
	if err != nil {
		return false, err
	}
	
	req.SetBasicAuth("OAuth", token)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "node-SecurityRoles-api")
	req.Header.Add("X-Tfs-Fedauthredirect", "Suppress")
	req.Header.Add("Connection", "close")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return true, nil
	} else if res.StatusCode == 401 {
		// The secret is determinately not verified
		return false, nil
	} else {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// verifyOrgPAT verifies if the Azure DevOps Personal Access Token is valid for a specific organization
func verifyOrgPAT(ctx context.Context, client *http.Client, token, org string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://dev.azure.com/"+org+"/_apis/projects", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth("", token)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	
	hasVerifiedRes, _ := common.ResponseContainsSubstring(res.Body, "lastUpdateTime")
	if res.StatusCode >= 200 && res.StatusCode < 300 && hasVerifiedRes {
		return true, nil
	} else if res.StatusCode == 401 {
		// The secret is determinately not verified
		return false, nil
	} else {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
