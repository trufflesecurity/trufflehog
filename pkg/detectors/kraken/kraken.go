package kraken

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"io"
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
	client = common.SaneHttpClient()

	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"kraken"}) + `\b([0-9A-Za-z\/\+=]{56}[ "'\r\n]{1})`)
	privKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kraken"}) + `\b([0-9A-Za-z\/\+=]{86,88}[ "'\r\n]{1})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("kraken")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	privKeyMatches := privKeyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, privKeyMatch := range privKeyMatches {
			if len(privKeyMatch) != 2 {
				continue
			}
			resPrivKeyMatch := bytes.TrimSpace(privKeyMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Kraken,
				Raw:          resMatch,
				RawV2:        append(resMatch, resPrivKeyMatch...),
			}

			if verify {

				apiNonce := strconv.FormatInt(time.Now().Unix(), 10)
				payload := url.Values{}
				payload.Add("nonce", apiNonce)

				b64DecodedSecret, _ := base64.StdEncoding.DecodeString(string(resPrivKeyMatch))
				signature := getKrakenSignature("/0/private/Balance", payload, b64DecodedSecret)

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.kraken.com/0/private/Balance", strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("API-Key", string(resMatch))
				req.Header.Add("API-Sign", signature)

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					out, _ := io.ReadAll(res.Body)
					if !bytes.Contains(out, []byte("Invalid key")) {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
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

// Code from https://docs.kraken.com/rest/#section/Authentication/Headers-and-Signature
func getKrakenSignature(url_path string, values url.Values, secret []byte) string {

	sha := sha256.New()
	sha.Write([]byte(values.Get("nonce") + values.Encode()))
	shasum := sha.Sum(nil)

	mac := hmac.New(sha512.New, secret)
	mac.Write(append([]byte(url_path), shasum...))
	macsum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Kraken
}
