package opsgenie

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"opsgenie"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Opsgenie
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"opsgenie"}
}

// FromData will find and optionally verify Opsgenie secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Opsgenie,
			Raw:          []byte(resMatch),
		}

		if verify {
			// Check for false positives
		    if detectors.IsKnownFalsePositive(match[0], append(detectors.DefaultFalsePositives, "opsgenie.com/alert/detail/"), true) {
		        continue
		    }
		    req, err := http.NewRequestWithContext(ctx, "GET", "https://api.opsgenie.com/v2/alerts", nil)
		    if err != nil {
			continue
		    }
		    req.Header.Add("Authorization", fmt.Sprintf("GenieKey %s", resMatch))
		    res, err := client.Do(req)
		    if err != nil {
			continue
		    }
		    defer res.Body.Close()

		    // Check for 200 status code
		    if res.StatusCode == 200 {
			var data map[string]interface{}
			err := json.NewDecoder(res.Body).Decode(&data)
			if err != nil {
			    s1.Verified = false
			    continue
			}

			// Check if "data" is one of the top-level attributes
			if _, ok := data["data"]; ok {
			    s1.Verified = true
			} else {
			    s1.Verified = false
			}
		    } else {
			s1.Verified = false

		    }
		}


		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}
