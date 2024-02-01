package azurebatch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	urlPat    = regexp.MustCompile(`https://(.{1,50})\.(.{1,50})\.batch\.azure\.com`)
	secretPat = regexp.MustCompile(`[A-Za-z0-9+/=]{88}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".batch.azure.com"}
}

// FromData will find and optionally verify Azurebatch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	urlMatches := urlPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, urlMatch := range urlMatches {

		for _, secretMatch := range secretMatches {

			endpoint := urlMatch[0]
			accountName := urlMatch[1]
			accountKey := secretMatch[0]

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureBatch,
				Raw:          []byte(endpoint),
				RawV2:        []byte(endpoint + accountKey),
				Redacted:     endpoint,
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				url := fmt.Sprintf("%s/applications?api-version=2020-09-01.12.0", endpoint)
				date := time.Now().UTC().Format(http.TimeFormat)
				stringToSign := fmt.Sprintf(
					"GET\n\n\n\n\napplication/json\n%s\n\n\n\n\n\n%s\napi-version:%s",
					date,
					strings.ToLower(fmt.Sprintf("/%s/applications", accountName)),
					"2020-09-01.12.0",
				)
				key, _ := base64.StdEncoding.DecodeString(accountKey)
				h := hmac.New(sha256.New, key)
				h.Write([]byte(stringToSign))
				signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", accountName, signature))
				req.Header.Set("Date", date)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					s1.Verified = true
				}

			}

			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(accountKey, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureBatch
}
