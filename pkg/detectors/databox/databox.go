package databox

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"databox"}) + common.BuildRegex(common.RegexPattern, "", 21))
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"databox"}
}

// FromData will find and optionally verify Databox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Databox,
			Raw:          []byte(resMatch),
		}
		if verify {
			data := fmt.Sprintf("%s:", resMatch)
			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			payload := strings.NewReader(`{
				"data":[
				  {
					"$sales": 420,
					"$visitors": 123000
				  }
				]
			  }`)

			req, err := http.NewRequestWithContext(ctx, "POST", "https://push.databox.com", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Accept", "application/vnd.databox.v2+json")
			req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
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
	return detectorspb.DetectorType_Databox
}

func (s Scanner) Description() string {
	return "Databox is a business analytics platform that pulls all your data into one place, so you can track performance and discover insights in real-time. Databox API keys can be used to access and modify data within your Databox account."
}
