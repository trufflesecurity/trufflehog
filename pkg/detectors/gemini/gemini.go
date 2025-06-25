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

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"master-", "account-"}
}

// FromData will find and optionally verify Gemini secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range idMatches {
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			resSecretMatch := strings.TrimSpace(secretMatch[0])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Gemini,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				req, err := constructRequest(ctx, resSecretMatch, resMatch)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func constructRequest(ctx context.Context, secret, keyID string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+accountDetail, &bytes.Buffer{})
	if err != nil {
		return nil, err
	}

	params := map[string]any{
		"request": accountDetail,
		"nonce":   time.Now().UnixNano(),
	}

	acct := strings.Split(keyID, "-")
	// Not entirely sure how to handle master account keys where one of the accounts is named "primary".
	if len(acct) > 1 && acct[0] == "master" {
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
		"X-GEMINI-APIKEY":    {keyID},
		"X-GEMINI-PAYLOAD":   {payload},
		"X-GEMINI-SIGNATURE": {signature},
		"Cache-Control":      {"no-cache"},
	}
	return req, err
}

func constructSignature(payload string, resSecretMatch string) string {
	h := hmac.New(sha512.New384, []byte(resSecretMatch))
	h.Write([]byte(payload))
	signature := hex.EncodeToString(h.Sum(nil))
	return signature
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gemini
}

func (s Scanner) Description() string {
	return "Gemini is a cryptocurrency exchange platform. API keys can be used to access and manage account details and perform transactions."
}
