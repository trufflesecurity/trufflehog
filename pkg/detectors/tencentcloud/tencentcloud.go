package tencentcloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

	// SecretId always starts with the "AKID" prefix followed by 32 alphanumeric characters.
	idPat = regexp.MustCompile(`\b(AKID[A-Za-z0-9]{32})\b`)
	// SecretKey is a generic 32-character alphanumeric string; it is paired with a SecretId.
	secretPat = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"AKID"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TencentCloud
}

func (s Scanner) Description() string {
	return "Tencent Cloud is a cloud computing platform offering compute, storage, database and 200+ other services. SecretId/SecretKey pairs grant programmatic access to the account's cloud resources."
}

// FromData will find and optionally verify Tencent Cloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[match[1]] = struct{}{}
	}

	secretMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	for id := range idMatches {
		for secret := range secretMatches {
			// Skip low-entropy secrets to reduce false positives from generic 32-char strings.
			if detectors.StringShannonEntropy(secret) < 3.0 {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_TencentCloud,
				Raw:          []byte(id),
				RawV2:        []byte(id + ":" + secret),
				Redacted:     id,
				SecretParts: map[string]string{
					"secret_id":  id,
					"secret_key": secret,
				},
			}

			if verify {
				isVerified, verificationErr := verifyMatch(ctx, s.getClient(), id, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, secret)
			}

			results = append(results, s1)

			// Once a SecretId is verified with a SecretKey, stop pairing it with other secrets.
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

const (
	verifyHost    = "cvm.tencentcloudapi.com"
	verifyService = "cvm"
	verifyAction  = "DescribeRegions"
	verifyVersion = "2017-03-12"
	verifyRegion  = "ap-guangzhou"
)

// tencentResponse models the envelope every Tencent Cloud 3.0 API returns.
// Authentication failures are reported with HTTP 200 and an Error block in the body.
type tencentResponse struct {
	Response struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

func verifyMatch(ctx context.Context, client *http.Client, secretID, secretKey string) (bool, error) {
	const payload = "{}"
	now := time.Now().UTC()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	date := now.Format("2006-01-02")

	// Build the TC3-HMAC-SHA256 authorization header.
	// https://www.tencentcloud.com/document/api/213/31574
	contentType := "application/json; charset=utf-8"
	canonicalHeaders := "content-type:" + contentType + "\nhost:" + verifyHost + "\n"
	signedHeaders := "content-type;host"
	hashedPayload := sha256Hex(payload)
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")

	credentialScope := date + "/" + verifyService + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		timestamp,
		credentialScope,
		sha256Hex(canonicalRequest),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, verifyService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	authorization := fmt.Sprintf(
		"TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretID, credentialScope, signedHeaders, signature,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+verifyHost+"/", strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Host", verifyHost)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("X-TC-Action", verifyAction)
	req.Header.Set("X-TC-Version", verifyVersion)
	req.Header.Set("X-TC-Timestamp", timestamp)
	req.Header.Set("X-TC-Region", verifyRegion)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	var parsed tencentResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false, err
	}

	// No error block means the signature was accepted and the credentials are valid.
	if parsed.Response.Error == nil {
		return true, nil
	}
	// Authentication errors are determinate: the credentials are invalid.
	if strings.HasPrefix(parsed.Response.Error.Code, "AuthFailure") {
		return false, nil
	}
	// Any other error code is unexpected; surface it as an indeterminate result.
	return false, fmt.Errorf("unexpected error code %q: %s", parsed.Response.Error.Code, parsed.Response.Error.Message)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}
