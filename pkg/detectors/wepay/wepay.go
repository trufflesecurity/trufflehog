package wepay

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.

	appIDPat = regexp.MustCompile(`\b(\d{6})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"wepay"}) + `\b([a-zA-Z0-9_?]{62})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"wepay"}
}

// FromData will find and optionally verify WePay secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	appIDmatches := appIDPat.FindAllStringSubmatch(dataStr, -1)

	resAppIDMatch := ""
	for _, appIDMatch := range appIDmatches {
		resAppIDMatch = strings.TrimSpace(appIDMatch[1])
	}

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_WePay,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://stage-api.wepay.com/payments?type=credit_card&credit_card=4003830171874018", nil)
			if err != nil {
				continue
			}
			req.Header.Add("App-Token", resMatch)
			req.Header.Add("App-Id", resAppIDMatch)
			req.Header.Add("Api-Version", "3.0")
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Unique-Key", "Unique-Key0")

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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_WePay
}

func (s Scanner) Description() string {
	return "WePay is an online payment service provider. WePay API keys can be used to process payments and access account information."
}
