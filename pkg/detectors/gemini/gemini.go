package gemini

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

const (
	baseURL       = "https://api.gemini.com"
	accountDetail = "/v1/account"
	account       = "primary"
)

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b((?:master-|account-)[0-9A-Za-z]{20})\b`)
	secretPat = regexp.MustCompile(`[A-Za-z0-9]{27,28}`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("master-"), []byte("account-")}
}

func (s Scanner) FromData(_ context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			resSecretMatch := bytes.TrimSpace(secretMatch[0])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Gemini,
				Raw:          resMatch,
				RawV2:        append(resMatch, resSecretMatch...),
			}

			if verify {
				req, err := constructRequest(resSecretMatch, resMatch)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive([]byte(resSecretMatch), detectors.DefaultFalsePositives, true) {
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

func constructRequest(secret, keyID []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", baseURL+accountDetail, &bytes.Buffer{})
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"request": accountDetail,
		"nonce":   time.Now().UnixNano(),
	}

	acct := bytes.Split(keyID, []byte("-"))
	if len(acct) > 1 && string(acct[0]) == "master" {
		params["account"] = account
	}

	reqStr, err := json.Marshal(&params)
	if err != nil {
		return nil, err
	}

	payload := base64.StdEncoding.EncodeToString(reqStr)
	signature := constructSignature(payload, secret)

	req.Header = http.Header{
		"Content-Type":       {"text/plain"},
		"Content-Length":     {"0"},
		"X-GEMINI-APIKEY":    {string(keyID)},
		"X-GEMINI-PAYLOAD":   {payload},
		"X-GEMINI-SIGNATURE": {signature},
		"Cache-Control":      {"no-cache"},
	}
	return req, err
}

func constructSignature(payload string, resSecretMatch []byte) string {
	h := hmac.New(sha512.New384, resSecretMatch)
	h.Write([]byte(payload))
	signature := hex.EncodeToString(h.Sum(nil))
	return signature
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gemini
}
