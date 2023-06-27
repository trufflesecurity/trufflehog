package pusherchannelkey

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

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

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	appMatches := appIdPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, appMatch := range appMatches {
		if len(appMatch) != 2 {
			continue
		}
		resappMatch := strings.TrimSpace(appMatch[1])

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}
			reskeyMatch := strings.TrimSpace(keyMatch[1])

			for _, secretMatch := range secretMatches {
				if len(secretMatch) != 2 {
					continue
				}
				ressecretMatch := strings.TrimSpace(secretMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_PusherChannelKey,
					Raw:          []byte(resappMatch),
					RawV2:        []byte(resappMatch + reskeyMatch),
				}

				if verify {

					method := "POST"
					path := "/apps/" + resappMatch + "/events"

					stringPayload := `{"channels":["my-channel"],"data":"{\"message\":\"hello world\"}","name":"my_event"}`
					payload := strings.NewReader(stringPayload)
					_bodyMD5 := md5.New()
					_bodyMD5.Write([]byte(stringPayload))
					md5 := hex.EncodeToString(_bodyMD5.Sum(nil))

					timestamp := strconv.FormatInt(time.Now().Unix(), 10)
					params := url.Values{
						"auth_key":       {reskeyMatch},
						"auth_timestamp": {timestamp},
						"auth_version":   {auth_version},
						"body_md5":       {md5},
					}

					usecd, _ := url.QueryUnescape(params.Encode())

					stringToSign := strings.Join([]string{method, path, usecd}, "\n")
					signature := hex.EncodeToString(hmacBytes([]byte(stringToSign), []byte(ressecretMatch)))

					md5Str := "https://api-ap1.pusher.com/apps/" + resappMatch + "/events?auth_key=" + reskeyMatch + "&auth_signature=" + signature + "&auth_timestamp=" + timestamp + "&auth_version=1.0&body_md5=" + md5

					req, err := http.NewRequestWithContext(ctx, method, md5Str, payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(ressecretMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
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
