package metrilo

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metrilo"}) + `\b([a-z0-9]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metrilo"}
}

// FromData will find and optionally verify Metrilo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Metrilo,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"time":1518004715732,"token": "` + resMatch + `" ,"platform":"Wordpress 4.2.7 / Woocommerce 3.5","pluginVersion":"1.1.0","params":{"id":"12","name":"Clothing","url":"https://dummysite.com"}}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://trk.mtrl.me/category", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Content-Length", `0`)
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
	return detectorspb.DetectorType_Metrilo
}

func (s Scanner) Description() string {
	return "Metrilo is an analytics and CRM platform for e-commerce. Metrilo API keys can be used to access and manage e-commerce data."
}
