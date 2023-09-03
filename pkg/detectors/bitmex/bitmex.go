package bitmex

import (
	"bytes"
	"context"
	"crypto/hmac"
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

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + string([]byte{32, 13, 10}) + `[0-9a-zA-Z\-\_]{24}` + string([]byte{32, 13, 10}))
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + string([]byte{32, 13, 10}) + `[0-9a-zA-Z\-\_]{48}` + string([]byte{32, 13, 10}))
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("bitmex")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bitmex,
				Raw:          resSecretMatch,
				RawV2:        append(resMatch, resSecretMatch...),
			}

			if verify {

				timestamp := strconv.FormatInt(time.Now().Unix()+5, 10)
				action := "GET"
				path := "/api/v1/user"
				payload := url.Values{}

				signature := getBitmexSignature(timestamp, string(resSecretMatch), action, path, payload.Encode())

				req, err := http.NewRequestWithContext(ctx, action, "https://www.bitmex.com"+path, bytes.NewReader([]byte(payload.Encode())))

				if err != nil {
					continue
				}
				req.Header.Add("api-expires", timestamp)
				req.Header.Add("api-key", string(resMatch))
				req.Header.Add("api-signature", signature)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}

						if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func getBitmexSignature(timeStamp string, secret string, action string, path string, payload string) string {

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(action + path + timeStamp + payload))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitmex
}
