package kucoin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
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
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"kucoin"}) + `\b([0-9a-f]{24})\b`)
	secretPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"kucoin"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	passphrasePat = regexp.MustCompile(detectors.PrefixRegex([]string{"kucoin"}) + `([ \r\n]{1}[!-~]{7,32}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kucoin"}
}

// FromData will find and optionally verify KuCoin secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	passphraseMatches := passphrasePat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		resKeyMatch := strings.TrimSpace(keyMatch[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			for _, passphraseMatch := range passphraseMatches {
				if len(passphraseMatch) != 2 {
					continue
				}
				resPassphraseMatch := strings.TrimSpace(passphraseMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_KuCoin,
					Raw:          []byte(resKeyMatch),
					RawV2:        []byte(resKeyMatch + resPassphraseMatch),
				}

				if verify {

					timestamp := strconv.FormatInt(time.Now().Unix()*1000, 10)
					method := "GET"
					endpoint := "/api/v1/accounts"
					bodyStr := ""
					apiVersion := "2"

					signature := getKucoinSignature(resSecretMatch, timestamp, method, endpoint, bodyStr)
					passPhrase := getKucoinPassphrase(resSecretMatch, resPassphraseMatch)

					req, err := http.NewRequest(method, "https://api.kucoin.com"+endpoint, nil)
					if err != nil {
						continue
					}
					req.Header.Add("KC-API-KEY", resKeyMatch)
					req.Header.Add("KC-API-SIGN", signature)
					req.Header.Add("KC-API-TIMESTAMP", timestamp)
					req.Header.Add("KC-API-PASSPHRASE", passPhrase)
					req.Header.Add("KC-API-KEY-VERSION", apiVersion)

					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resKeyMatch, detectors.DefaultFalsePositives, true) {
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
	}

	return results, nil
}

func getKucoinPassphrase(apiSecret string, apiPassphrase string) string {

	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(apiPassphrase))
	macsum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(macsum)
}

func getKucoinSignature(apiSecret string, timestamp string, method string, endpoint string, bodyStr string) string {

	preHashStr := timestamp + method + endpoint + bodyStr
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(preHashStr))
	macsum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_KuCoin
}
