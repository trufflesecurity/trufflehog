package azureactivedirectoryapplicationsecret

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([a-zA-Z0-9_+.=~-]{40})\b`)
	clientPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure client"}) + common.BuildRegex(common.RegexPattern, "-", 36))
	tenantPat = regexp.MustCompile(detectors.PrefixRegex([]string{"azure tenant"}) + common.BuildRegex(common.RegexPattern, "-", 36))
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure"}
}

// FromData will find and optionally verify AzureActiveDirectoryApplicationSecret secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	uniqueClientMatches := make(map[string]struct{})
	for _, clientMatch := range clientPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueClientMatches[clientMatch[1]] = struct{}{}
	}
	uniqueTenantMatches := make(map[string]struct{})
	for _, tenantMatch := range tenantPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTenantMatches[tenantMatch[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		for clientMatch := range uniqueClientMatches {
			for tenantMatch := range uniqueTenantMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_AzureActiveDirectoryApplicationSecret,
					Raw:          []byte(match),
					RawV2:        []byte(match + clientMatch + tenantMatch),
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}
					isVerified, extraData, verificationErr := verifyMatch(ctx, client, match, clientMatch, tenantMatch)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					s1.SetVerificationError(verificationErr, match)
				}

				// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
				if !s1.Verified && detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
					continue
				}
				if !s1.Verified && detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
					continue
				}
				if !s1.Verified && detectors.IsKnownFalsePositive(match, detectors.DefaultFalsePositives, true) {
					continue
				}

				results = append(results, s1)
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token, clientId, tenantId string) (bool, map[string]string, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default")
	data.Set("client_secret", token)
	encodedData := data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.microsoftonline.com/"+tenantId+"/oauth2/v2.0/token", strings.NewReader(encodedData))
	if err != nil {
		return false, nil, nil
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil, nil
	} else if res.StatusCode == 401 {
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	} else {
		err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureActiveDirectoryApplicationSecret
}
