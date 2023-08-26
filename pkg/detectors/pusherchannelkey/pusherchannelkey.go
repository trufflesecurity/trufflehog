package pusherchannelkey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	appIdPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"pusher"}) + `\b([0-9]{7})\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"key"}) + `\b([a-z0-9]{20})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pusher"}) + `\b([a-z0-9]{20})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("pusher")}
}

const (
	auth_version = "1.0"
)

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	appMatches := appIdPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, appMatch := range appMatches {
		if len(appMatch) != 2 {
			continue
		}
		resappMatch := bytes.TrimSpace(appMatch[1])

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}
			reskeyMatch := bytes.TrimSpace(keyMatch[1])

			for _, secretMatch := range secretMatches {
				if len(secretMatch) != 2 {
					continue
				}
				ressecretMatch := bytes.TrimSpace(secretMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_PusherChannelKey,
					Raw:          resappMatch,
					RawV2:        append(resappMatch, reskeyMatch...),
				}

				if verify {

					method := "POST"
					path := []byte("/apps/" + string(resappMatch) + "/events")

					payload := []byte(`{"channels":["my-channel"],"data":"{\"message\":\"hello world\"}","name":"my_event"}`)
					_bodyMD5 := md5.New()
					_bodyMD5.Write(payload)
					md5 := hex.EncodeToString(_bodyMD5.Sum(nil))

					timestamp := strconv.FormatInt(time.Now().Unix(), 10)
					params := url.Values{
						"auth_key":       {string(reskeyMatch)},
						"auth_timestamp": {timestamp},
						"auth_version":   {auth_version},
						"body_md5":       {md5},
					}

					usecd, _ := url.QueryUnescape(params.Encode())

					stringToSign := bytes.Join([][]byte{[]byte(method), path, []byte(usecd)}, []byte("\n"))
					signature := hex.EncodeToString(hmacBytes(stringToSign, ressecretMatch))

					md5Str := "https://api-ap1.pusher.com/apps/" + string(resappMatch) + "/events?auth_key=" + string(reskeyMatch) + "&auth_signature=" + signature + "&auth_timestamp=" + timestamp + "&auth_version=1.0&body_md5=" + md5

					req, err := http.NewRequestWithContext(ctx, method, md5Str, bytes.NewReader(payload))
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
