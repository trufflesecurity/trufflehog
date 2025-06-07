package square

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// more context to be added if this is too generic
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"square"}) + `(EAAA[a-zA-Z0-9\-\+\=]{60})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"EAAA"}
}

// FromData will find and optionally verify Square secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Surprisingly there are still a lot of false positives! So, also doing substring check for square.
	if !strings.Contains(strings.ToLower(dataStr), "square") {
		return
	}

	secMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	for _, secMatch := range secMatches {
		resMatch := strings.TrimSpace(secMatch[1])

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Square,
			Raw:          []byte(resMatch),
		}
		result.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/square/",
		}

		if verify {
			// there are a few endpoints we can check, but templates seems the least sensitive.
			// 403 will be issued if the scope is wrong but the key is correct
			baseURL := "https://connect.squareupsandbox.com/v2/merchants"

			client := common.SaneHttpClient()

			// test `merchants` scope - its commonly allowed and low sensitivity
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Content-Type", "application/json")
			// unclear if this version needs to be set or matters, seems to work without, but docs want it
			// req.Header.Add("Square-Version", "2020-08-12")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close() // The request body is unused.

				// 200 means good key and has `merchants` scope - default allowed by square
				// 401 is bad key
				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					result.Verified = true
				}
			}
			result.AnalysisInfo = map[string]string{"key": resMatch}
		}

		results = append(results, result)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Square
}

func (s Scanner) Description() string {
	return "Square is a financial services and mobile payment company. Square API keys can be used to access and manage payments, transactions, and other financial data."
}
