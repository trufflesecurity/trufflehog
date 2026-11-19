package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Integration key is of 20 characters with only capital alphabets and digits.
	integrationKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo"}) + `\b(DI[A-Z0-9]{18})\b`)

	// Secret key is of 40 characters with only alphabets and digits.
	secretKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo"}) + `\b([A-Za-z0-9]{40})\b`)

	// Host is usually a subdomain of duosecurity.com e.g api-21321awda.duosecurity.com
	apiHost = regexp.MustCompile(`\b([a-z0-9-]{6,}\.duosecurity\.com)\b`)
)

const (
	adminAPIPath = "/admin/v1/info/summary" // https://duo.com/docs/adminapi#account-info
	authAPIPath  = "/auth/v2/check"         // https://duo.com/docs/authapi#check

	adminApplication = "Admin API"
	authApplication  = "Auth API"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"duosecurity"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Duo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueHosts := make(map[string]struct{})
	uniqueIntKeys := make(map[string]struct{})
	uniqueSecretKeys := make(map[string]struct{})
	for _, match := range apiHost.FindAllStringSubmatch(dataStr, -1) {
		uniqueHosts[match[1]] = struct{}{}
	}
	for _, match := range integrationKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIntKeys[match[1]] = struct{}{}
	}
	for _, match := range secretKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretKeys[match[1]] = struct{}{}
	}
	for host := range uniqueHosts {
		for apiKey := range uniqueIntKeys {
			for apiSecret := range uniqueSecretKeys {
				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_Duo,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, apiKey, apiSecret)),
					ExtraData: map[string]string{
						"application": adminApplication,
					},
					SecretParts: map[string]string{
						"host":        host,
						"ikey":        apiKey,
						"skey":        apiSecret,
						"application": adminApplication,
					},
				}
				if verify {
					verified, application, verificationErr := verifyMatch(ctx, s.getClient(), host, apiKey, apiSecret)
					s1.ExtraData["application"] = application
					s1.SecretParts["application"] = application
					s1.SetVerificationError(verificationErr, host, apiKey, apiSecret)
					s1.Verified = verified
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

// verifyMatch checks the credentials against the Admin API, then the Auth API, and
// returns whether they are valid and which application they belong to.
//
// Duo can answer 403 (40301, "Access forbidden") before it checks the signature, so a
// 403 says nothing about the secret key. Only a 200 from either API proves the
// credentials valid. A 401 from the Auth API proves them invalid, because Admin API keys
// get a 403 there. The Admin API returns 401 for every key that is not an Admin API
// key, so its 401 proves the credentials invalid only once the Auth API has identified
// them as Admin API keys with a 403. Any other combination is reported as a
// verification error.
func verifyMatch(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
) (bool, string, error) {
	adminStatus, adminErr := duoRequestStatus(ctx, client, host, ikey, skey, adminAPIPath)
	if adminErr == nil && adminStatus == http.StatusOK {
		return true, adminApplication, nil
	}

	authStatus, authErr := duoRequestStatus(ctx, client, host, ikey, skey, authAPIPath)
	if authErr == nil && authStatus == http.StatusOK {
		return true, authApplication, nil
	}

	authAnswered := authErr == nil
	if authAnswered && (authStatus == http.StatusUnauthorized ||
		(authStatus == http.StatusForbidden && adminErr == nil && adminStatus == http.StatusUnauthorized)) {
		return false, adminApplication, nil
	}
	if adminErr != nil {
		return false, adminApplication, adminErr
	}
	if authErr != nil {
		return false, adminApplication, authErr
	}
	return false, adminApplication, fmt.Errorf(
		"indeterminate Duo verification: admin API returned HTTP %d, auth API returned HTTP %d",
		adminStatus, authStatus,
	)
}

// duoRequestStatus sends a signed GET request to the given Duo API path and returns the
// HTTP status code without interpreting it.
func duoRequestStatus(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
	path string,
) (int, error) {

	timestamp := time.Now().UTC().Format(http.TimeFormat)

	// Canonical request string
	canonical := strings.Join([]string{
		timestamp,
		http.MethodGet,
		host,
		path,
		"",
	}, "\n")

	// HMAC signature
	mac := hmac.New(sha1.New, []byte(skey))
	_, _ = mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Authorization header
	auth := base64.StdEncoding.EncodeToString(
		[]byte(ikey + ":" + signature),
	)

	// Build request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://"+host+path,
		nil,
	)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Date", timestamp)

	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	return res.StatusCode, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Duo
}

func (s Scanner) Description() string {
	return "Duo is a security platform that provides multi-factor authentication and identity management services."
}
