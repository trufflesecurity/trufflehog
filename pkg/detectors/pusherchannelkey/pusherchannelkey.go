package pusherchannelkey

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	appIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pusher"}) + `\b([0-9]{7})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"key"}) + `\b([a-z0-9]{20})\b`)
	// this is currently incorrect, should be a callback from the API
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pusher"}) + `\b([a-z0-9]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pusher"}
}

const (
	auth_version = "1.0"
)

// FromData will find and optionally verify PusherChannelKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeyMatches, uniqueAppMatches, uniqueSecretMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, keyMatch := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[keyMatch[1]] = struct{}{}
	}

	for _, appMatch := range appIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAppMatches[appMatch[1]] = struct{}{}
	}

	for _, secretMatch := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[secretMatch[1]] = struct{}{}
	}

	for app := range uniqueAppMatches {
		for key := range uniqueKeyMatches {
			for secret := range uniqueSecretMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_PusherChannelKey,
					Raw:          []byte(app),
					RawV2:        []byte(app + key),
				}

				if verify {
					isVerified, verificationErr := verifyPusherChannelKey(ctx, client, app, key, secret)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr)
				}

				results = append(results, s1)
			}

		}

	}

	return results, nil
}
func hmacBytes(toSign, secret []byte) []byte {
	_authSignature := hmac.New(sha256.New, secret)
	_authSignature.Write(toSign)
	return _authSignature.Sum(nil)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PusherChannelKey
}

func (s Scanner) Description() string {
	return "Pusher is a service for adding real-time functionality to web and mobile apps. Pusher Channel keys can be used to authenticate and send messages to channels."
}

func verifyPusherChannelKey(ctx context.Context, client *http.Client, app, key, secret string) (bool, error) {
	method := "POST"
	path := "/apps/" + app + "/events"

	stringPayload := `{"channels":["my-channel"],"data":"{\"message\":\"hello world\"}","name":"my_event"}`
	payload := strings.NewReader(stringPayload)
	_bodyMD5 := md5.New()
	_bodyMD5.Write([]byte(stringPayload))
	hash := hex.EncodeToString(_bodyMD5.Sum(nil))

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	params := url.Values{
		"auth_key":       {key},
		"auth_timestamp": {timestamp},
		"auth_version":   {auth_version},
		"body_md5":       {hash},
	}

	usecd, _ := url.QueryUnescape(params.Encode())

	stringToSign := strings.Join([]string{method, path, usecd}, "\n")
	signature := hex.EncodeToString(hmacBytes([]byte(stringToSign), []byte(secret)))

	md5Str := "https://api-ap1.pusher.com/apps/" + app + "/events?auth_key=" + key + "&auth_signature=" + signature + "&auth_timestamp=" + timestamp + "&auth_version=1.0&body_md5=" + hash

	req, err := http.NewRequestWithContext(ctx, method, md5Str, payload)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
