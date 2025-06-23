package bitmex

import (
	"context"
	"crypto/hmac"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + `([ \r\n]{1}[0-9a-zA-Z\-\_]{24}[ \r\n]{1})`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + `([ \r\n]{1}[0-9a-zA-Z\-\_]{48}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitmex"}
}

// FromData will find and optionally verify Bitmex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bitmex,
				Raw:          []byte(resSecretMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				isVerified, verificationErr := verifyBitmex(ctx, client, resMatch, resSecretMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitmex
}

func (s Scanner) Description() string {
	return "Bitmex is a cryptocurrency exchange and derivative trading platform. Bitmex API keys can be used to access and trade on the platform programmatically."
}

// docs: https://www.bitmex.com/app/apiKeysUsage
func verifyBitmex(ctx context.Context, client *http.Client, key, secret string) (bool, error) {
	timestamp := strconv.FormatInt(time.Now().Unix()+5, 10)
	action := "GET"
	path := "/api/v1/user"
	payload := url.Values{}

	signature := getBitmexSignature(timestamp, secret, action, path, payload.Encode())

	req, err := http.NewRequestWithContext(ctx, action, "https://www.bitmex.com"+path, strings.NewReader(payload.Encode()))
	if err != nil {
		return false, err
	}

	req.Header.Add("api-expires", timestamp)
	req.Header.Add("api-key", key)
	req.Header.Add("api-signature", signature)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func getBitmexSignature(timeStamp string, secret string, action string, path string, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(action + path + timeStamp + payload))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}
