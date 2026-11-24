package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	duoCodeInvalidSignature = 40103
	duoCodeAccessForbidden  = 40301
)

type duoReply struct {
	status int
	code   int
}

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
// Only a 200 from either API proves the credentials valid, and only error code 40103
// (invalid signature) from either API proves them invalid: that API recognized the
// integration key and rejected the secret key. Other responses are reported as a verification error.
func verifyMatch(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
) (bool, string, error) {
	admin, adminErr := duoRequest(ctx, client, host, ikey, skey, adminAPIPath)
	if adminErr == nil && admin.status == http.StatusOK {
		return true, adminApplication, nil
	}

	auth, authErr := duoRequest(ctx, client, host, ikey, skey, authAPIPath)
	if authErr == nil && auth.status == http.StatusOK {
		return true, authApplication, nil
	}

	if (adminErr == nil && admin.code == duoCodeInvalidSignature) ||
		(authErr == nil && auth.code == duoCodeInvalidSignature) {
		return false, adminApplication, nil
	}
	if adminErr != nil {
		return false, adminApplication, adminErr
	}
	if authErr != nil {
		return false, adminApplication, authErr
	}

	msg := fmt.Sprintf(
		"indeterminate Duo verification: admin API returned HTTP %d (code %d), auth API returned HTTP %d (code %d)",
		admin.status, admin.code, auth.status, auth.code,
	)
	if admin.code == duoCodeAccessForbidden {
		msg += `; an Admin API integration needs the "Grant read information" permission to be verified`
	}
	return false, adminApplication, errors.New(msg)
}

// duoRequest sends a signed GET request to the given Duo API path and returns the HTTP
// status and Duo error code without interpreting them.
func duoRequest(
	ctx context.Context,
	client *http.Client,
	host, ikey, skey string,
	path string,
) (duoReply, error) {

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
		return duoReply{}, err
	}

	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Date", timestamp)

	res, err := client.Do(req)
	if err != nil {
		return duoReply{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	reply := duoReply{status: res.StatusCode}
	if res.StatusCode != http.StatusOK {
		var body struct {
			Code int `json:"code"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&body) == nil {
			reply.code = body.Code
		}
	}
	return reply, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Duo
}

func (s Scanner) Description() string {
	return "Duo is a security platform that provides multi-factor authentication and identity management services."
}
