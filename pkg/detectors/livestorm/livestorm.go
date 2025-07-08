package livestorm

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"livestorm"}) + `\b(eyJhbGciOiJIUzI1NiJ9\.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi[0-9A-Z-a-z]{134}\.[0-9A-Za-z\-\_]{43}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"livestorm"}
}

// FromData will find and optionally verify Livestorm secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Livestorm,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.livestorm.co/v1/ping", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", resMatch)
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
	return detectorspb.DetectorType_Livestorm
}

func (s Scanner) Description() string {
	return "Livestorm is a video communication platform for webinars, meetings, and virtual events. Livestorm API keys can be used to interact with Livestorm services programmatically."
}
