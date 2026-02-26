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

	// Integration key is of 20 characters with only capital alphabets and digits.
	integrationKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo"}) + `\b(DI[A-Z0-9]{18})\b`)

	// Secret key is of 40 characters with only alphabets and digits.
	secretKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"duo"}) + `\b([A-Za-z0-9]{40})\b`)

	// Host is usually a subdomain of duosecurity.com e.g api-21321awda.duosecurity.com
	apiHost = regexp.MustCompile(`\b([a-z0-9-]{6,}\.duosecurity\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"duo"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify DeepSeek secrets in a given set of bytes.
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
					DetectorType: detectorspb.DetectorType_Duo,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", host, apiKey, apiSecret)),
					ExtraData: map[string]string{
						"application": "Admin API",
					},
				}
				if verify {
					verified, verificationErr := VerifyAdminToken(ctx, s.getClient(), host, apiKey, apiSecret)
					if !verified {
						verified, verificationErr = VerifyAuthToken(ctx, s.getClient(), host, apiKey, apiSecret)
						s1.ExtraData["application"] = "Auth API"
					}
					s1.SetVerificationError(verificationErr, host, apiKey, apiSecret)
					s1.Verified = verified
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

// returns verfied=true if credentials are valid and belong to auth api, false if creds are invalid, and error if creds belong to auth api or for anything else (e.g., network error)
func VerifyAuthToken(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
) (bool, error) {
	// Docs: https://duo.com/docs/authapi#check
	return verifyDuoRequest(
		ctx,
		client,
		host,
		ikey,
		skey,
		"/auth/v2/check",
	)
}

// returns 401 unauthorized if credentials are invalid, 200 OK if valid, and error for anything else
func VerifyAdminToken(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
) (bool, error) {
	// Docs: https://duo.com/docs/adminapi#account-info
	return verifyDuoRequest(
		ctx,
		client,
		host,
		ikey,
		skey,
		"/admin/v1/info/summary",
	)
}

func verifyDuoRequest(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
	path string,
) (bool, error) {

	// Duo-required timestamp (RFC1123, UTC, literal GMT)
	timestamp := time.Now().UTC().Format(time.RFC1123)

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
		return false, err
	}

	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Date", timestamp)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Duo
}

func (s Scanner) Description() string {
	return "Duo is a security platform that provides multi-factor authentication and identity management services."
}
