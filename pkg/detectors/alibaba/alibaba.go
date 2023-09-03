package alibaba

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
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

	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{30})\b`)
	idPat  = regexp.MustCompile(`\b(LTAI[a-zA-Z0-9]{17,21})[\"';\s]*`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("LTAI")}
}

func randString(n int) string {
	const alphanum = "0123456789abcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	_, _ = rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func GetSignature(input, key string) string {
	key_for_sign := []byte(key)
	h := hmac.New(sha1.New, key_for_sign)
	h.Write([]byte(input))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func buildStringToSign(method, input string) string {
	filter := strings.Replace(input, "+", "%20", -1)
	filter = strings.Replace(filter, "%7E", "~", -1)
	filter = strings.Replace(filter, "*", "%2A", -1)
	filter = method + "&%2F&" + url.QueryEscape(filter)
	return filter
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Alibaba,
				Raw:          resMatch,
				RawV2:        append(resMatch, resIdMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "http://ecs.aliyuncs.com/?", nil)
				if err != nil {
					continue
				}
				dateISO := time.Now().UTC().Format("2006-01-02T15:04:05Z07:00")
				params := req.URL.Query()
				params.Add("AccessKeyId", string(resIdMatch))
				params.Add("Action", "DescribeRegions")
				params.Add("Format", "JSON")
				params.Add("SignatureMethod", "HMAC-SHA1")
				params.Add("SignatureNonce", randString(16))
				params.Add("SignatureVersion", "1.0")
				params.Add("Timestamp", dateISO)
				params.Add("Version", "2014-05-26")

				stringToSign := buildStringToSign(req.Method, params.Encode())
				signature := GetSignature(stringToSign, string(resMatch)+"&") // Get Signature HMAC SHA1
				params.Add("Signature", signature)
				req.URL.RawQuery = params.Encode()

				req.Header.Add("Content-Type", "text/xml;charset=utf-8")
				req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Alibaba
}
