package refiner

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"refiner"}) + `\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"refiner"}
}

// FromData will find and optionally verify Refiner secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Refiner,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader("id=Your-User-Id&event=Your%20event%20name")
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.refiner.io/v1/identify-user", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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
	return detectorspb.DetectorType_Refiner
}

func (s Scanner) Description() string {
	return "Refiner is a user feedback platform. Refiner keys can be used to authenticate and identify users within the Refiner platform."
}
