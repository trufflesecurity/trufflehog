package azuresastoken

import (
	"context"
	"fmt"
	"io"
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

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// microsoft storage resource naming rules: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftstorage:~:text=format%3A%0AVaultName_KeyName_KeyVersion.-,Microsoft.Storage,-Expand%20table
	urlPat = regexp.MustCompile(`https:\/\/[a-zA-Z0-9][a-z0-9_-]{1,22}[a-zA-Z0-9]\.blob\.core\.windows\.net\/[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?(?:\/[a-zA-Z0-9._-]+)*`)

	keyPat = regexp.MustCompile(
		detectors.PrefixRegex([]string{"azure", "sas", "token", "blob", ".blob.core.windows.net"}) +
			`(sp=[racwdli]+&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z(&spr=https)?(?:,https)?&sv=\d{4}-\d{2}-\d{2}&sr=[bcfso]&sig=[a-zA-Z0-9%]{10,})`)
)

func (s Scanner) Keywords() []string {
	return []string{
		"azure",
		".blob.core.windows.net",
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureSasToken
}

func (s Scanner) Description() string {
	return "An Azure Shared Access Signature (SAS) token is a time-limited, permission-based URL query string that grants secure, granular access to Azure Storage resources (e.g., blobs, containers, files) without exposing account keys."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// deduplicate urlMatches
	urlMatchesUnique := make(map[string]struct{})
	for _, urlMatch := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		urlMatchesUnique[urlMatch[0]] = struct{}{}
	}

	// deduplicate keyMatches
	keyMatchesUnique := make(map[string]struct{})
	for _, keyMatch := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatchesUnique[keyMatch[1]] = struct{}{}
	}

	// Check results.
	for url := range urlMatchesUnique {
		for key := range keyMatchesUnique {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureSasToken,
				Raw:          []byte(url),
				RawV2:        []byte(url + key),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, url, key, true)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, url, key string, retryOn403 bool) (bool, error) {
	urlWithToken := url + "?" + key
	fmt.Println(urlWithToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlWithToken, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	fmt.Println(string(bodyBytes))

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		if retryOn403 && strings.Contains(string(bodyBytes), "Signature did not match") {
			// need to add additional query paramters for container urls
			// https://stackoverflow.com/questions/25038429/azure-shared-access-signature-signature-did-not-match
			return verifyMatch(ctx, client, url, key+"&comp=list&restype=container", false)
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
