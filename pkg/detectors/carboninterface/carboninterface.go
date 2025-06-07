package carboninterface

import (
	"context"
	"fmt"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"carboninterface"}) + `\b([a-zA-Z0-9]{21})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"carboninterface"}
}

// FromData will find and optionally verify CarbonInterface secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CarbonInterface,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"type":"flight","passengers":2,"legs":[{"departure_airport":"sfo","destination_airport":"yyz"},{"departure_airport":"yyz","destination_airport":"sfo"}]}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://www.carboninterface.com/api/v1/estimates", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Content-type", "application/json")
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
	return detectorspb.DetectorType_CarbonInterface
}

func (s Scanner) Description() string {
	return "CarbonInterface provides an API for estimating carbon emissions for various activities. The API keys can be used to access and utilize this service."
}
