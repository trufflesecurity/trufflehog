package paymongo

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"paymongo"}) + `\b([a-zA-Z0-9_]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"paymongo"}
}

// FromData will find and optionally verify Paymongo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Paymongo,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"data":{"attributes":{"type":"paymaya"}}}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.paymongo.com/v1/payment_methods", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.SetBasicAuth(resMatch, "")
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
	return detectorspb.DetectorType_Paymongo
}

func (s Scanner) Description() string {
	return "PayMongo is a payment processing platform in the Philippines. PayMongo API keys can be used to access and manage payment methods, transactions, and other related data."
}
