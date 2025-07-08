package twelvedata

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
	"strings"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twelvedata"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twelvedata"}
}

// FromData will find and optionally verify TwelveData secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_TwelveData,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.twelvedata.com/earliest_timestamp?symbol=AAPL&interval=1day&apikey="+resMatch, nil)
			if err != nil {
				continue
			}

			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)

				// if client_id and client_secret is valid -> 403 {"error":"invalid_grant","error_description":"Invalid authorization code"}
				// if invalid -> 401 {"error":"access_denied","error_description":"Unauthorized"}
				// ingenious!

				if !strings.Contains(body, "401") {
					s1.Verified = true
				}

			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TwelveData
}

func (s Scanner) Description() string {
	return "TwelveData provides financial data APIs for stock, forex, cryptocurrency, and more. TwelveData API keys can be used to access and retrieve this financial data."
}
