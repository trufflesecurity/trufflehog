package azuresastoken

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// microsoft storage resource naming rules: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules#microsoftstorage:~:text=format%3A%0AVaultName_KeyName_KeyVersion.-,Microsoft.Storage,-Expand%20table
	urlPat = regexp.MustCompile(`https://([a-zA-Z0-9][a-z0-9_-]{1,22}[a-zA-Z0-9])\.blob\.core\.windows\.net/[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?(?:/[a-zA-Z0-9._-]+)*`)

	// A SAS token is a query string of `&`-joined `key=value` pairs. The parameters
	// can appear in any order, and values may be URL-encoded (e.g. Azure Storage
	// Explorer encodes the `:` in the timestamps as %3A and the `+`, `/`, `=` in the
	// signature as %2B, %2F, %3D). Rather than enumerate every permutation in one
	// regex, match a contiguous run of query parameters and validate the SAS-specific
	// parameters in keyMatchIsSASToken below. This keeps detection order-independent.
	sasQueryPat = regexp.MustCompile(`[a-z]{2,4}=[^&\s"'<>]+(?:&[a-z]{2,4}=[^&\s"'<>]+)+`)

	// Validators for the individual SAS parameters. The `sp` permission set and `sr`
	// resource set match the formats the previous, order-locked regex accepted.
	spValuePat = regexp.MustCompile(`^[racwdli]+$`)
	svValuePat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	srValuePat = regexp.MustCompile(`^[bcfso]$`)
	// The `:` separators may be URL-encoded; percent-encoding hex digits are
	// case-insensitive per RFC 3986, so accept both %3A and %3a.
	timeValuePat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}(?::|%3[Aa])\d{2}(?::|%3[Aa])\d{2}Z$`)
	sigValuePat  = regexp.MustCompile(`^[a-zA-Z0-9%+/=]{10,}$`)
	sipValuePat  = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}(?:-\d{1,3}(?:\.\d{1,3}){3})?$`)

	invalidStorageAccounts = simple.NewCache[struct{}]()

	errNoSuchHost = errors.New("no such host")
)

func (s Scanner) Keywords() []string {
	return []string{
		"azure",
		".blob.core.windows.net",
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AzureSasToken
}

func (s Scanner) Description() string {
	return "An Azure Shared Access Signature (SAS) token is a time-limited, permission-based URL query string that grants secure, granular access to Azure Storage resources (e.g., blobs, containers, files) without exposing account keys."
}

// keyMatchIsSASToken reports whether a matched query-parameter run is a Azure
// Storage SAS token. The required parameters may appear in any order; values may
// be URL-encoded. This reproduces the validations the previous order-locked regex
// enforced (permission set, resource type, timestamp shape, signature, optional IP)
// without depending on parameter order.
func keyMatchIsSASToken(query string) bool {
	params := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		params[key] = value
	}

	sp, ok := params["sp"]
	if !ok || !spValuePat.MatchString(sp) {
		return false
	}
	sv, ok := params["sv"]
	if !ok || !svValuePat.MatchString(sv) {
		return false
	}
	sr, ok := params["sr"]
	if !ok || !srValuePat.MatchString(sr) {
		return false
	}
	sig, ok := params["sig"]
	if !ok || !sigValuePat.MatchString(sig) {
		return false
	}

	// A SAS token carries a start time, an expiry time, or both; any present one
	// must be well-formed.
	st, hasStart := params["st"]
	se, hasExpiry := params["se"]
	if !hasStart && !hasExpiry {
		return false
	}
	if hasStart && !timeValuePat.MatchString(st) {
		return false
	}
	if hasExpiry && !timeValuePat.MatchString(se) {
		return false
	}

	// The IP restriction is optional, but must be a valid address or range if set.
	if sip, ok := params["sip"]; ok && !sipValuePat.MatchString(sip) {
		return false
	}

	return true
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("azuresas")

	dataStr := string(data)

	// deduplicate urlMatches
	urlMatchesUnique := make(map[string]string)
	for _, urlMatch := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		urlMatchesUnique[urlMatch[0]] = urlMatch[1]
	}

	// deduplicate keyMatches
	keyMatchesUnique := make(map[string]struct{})
	for _, keyMatch := range sasQueryPat.FindAllString(dataStr, -1) {
		if keyMatchIsSASToken(keyMatch) {
			keyMatchesUnique[keyMatch] = struct{}{}
		}
	}

	// Check results.
UrlLoop:
	for url, storageAccount := range urlMatchesUnique {
		for key := range keyMatchesUnique {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_AzureSasToken,
				Raw:          []byte(url),
				SecretParts: map[string]string{
					"url": url,
					"key": key,
				},
				RawV2: []byte(url + key),
			}

			if verify {
				if invalidStorageAccounts.Exists(storageAccount) {
					logger.V(3).Info("Skipping invalid storage account", "storage account", storageAccount)
					break
				}

				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, url, key, true)
				s1.Verified = isVerified

				if verificationErr != nil {
					if errors.Is(verificationErr, errNoSuchHost) {
						invalidStorageAccounts.Set(storageAccount, struct{}{})
						continue UrlLoop
					}
					s1.SetVerificationError(verificationErr, key)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func verifyMatch(ctx context.Context, client *http.Client, url, key string, retryOn403 bool) (bool, error) {
	urlWithToken := url + "?" + key

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlWithToken, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoSuchHost
		}
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		if retryOn403 && strings.Contains(string(bodyBytes), "Signature did not match") {
			// need to add additional query parameters for container urls
			// https://stackoverflow.com/questions/25038429/azure-shared-access-signature-signature-did-not-match
			return verifyMatch(ctx, client, url, key+"&comp=list&restype=container", false)
		}
		if strings.Contains(string(bodyBytes), "AuthorizationFailure") && strings.Contains(key, "&sip=") {
			return false, fmt.Errorf("SAS token is restricted to specific IP addresses")
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
