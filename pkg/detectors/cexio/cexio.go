package cexio

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
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client    = common.SaneHttpClient()
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([0-9A-Za-z]{24,27})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([0-9A-Za-z]{24,27})\b`)
	userIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([a-z]{2}[0-9]{9})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("cexio"), []byte("cex.io")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)
	userIdMatches := userIdPat.FindAllSubmatch(data, -1)

	for _, userIdMatch := range userIdMatches {
		if len(userIdMatch) != 2 {
			continue
		}
		resUserIdMatch := bytes.TrimSpace(userIdMatch[1])

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}
			resKeyMatch := bytes.TrimSpace(keyMatch[1])

			for _, secretMatch := range secretMatches {
				if len(secretMatch) != 2 {
					continue
				}
				resSecretMatch := bytes.TrimSpace(secretMatch[1])
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_CexIO,
					Raw:          resKeyMatch,
					RawV2:        append(resUserIdMatch, resSecretMatch...),
				}
				if verify {
					timestamp := strconv.FormatInt(time.Now().Unix()*1000, 10)
					signature := getCexIOPassphrase(string(resSecretMatch), string(resKeyMatch), timestamp, string(resUserIdMatch))
					payload := url.Values{}
					payload.Add("key", string(resKeyMatch))
					payload.Add("signature", signature)
					payload.Add("nonce", timestamp)

					req, err := http.NewRequestWithContext(ctx, "POST", "https://cex.io/api/balance/", strings.NewReader(payload.Encode()))
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						}

						if detectors.IsKnownFalsePositive(resUserIdMatch, detectors.DefaultFalsePositives, true) || detectors.IsKnownFalsePositive(resKeyMatch, detectors.DefaultFalsePositives, true) || detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

func getCexIOPassphrase(apiSecret string, apiKey string, nonce string, userId string) string {

	msg := nonce + userId + apiKey
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(msg))
	macsum := mac.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(macsum))
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CexIO
}
