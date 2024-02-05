package api2cart

import (
	"context"
	"encoding/json"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"api2cart"}) + `\b([0-9a-f]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"api2cart"}
}

// FromData will find and optionally verify Api2Cart secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Api2Cart,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.api2cart.com/v1.1/account.cart.list.json?api_key=%s", resMatch), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				body, errBody := io.ReadAll(res.Body)

				var result Response
				if errBody == nil {
					if err := json.Unmarshal(body, &result); err != nil {
						continue
					}

					if res.StatusCode >= 200 && res.StatusCode < 300 && result.ReturnCode == 0 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

type Response struct {
	ReturnCode int `json:"return_code"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Api2Cart
}
