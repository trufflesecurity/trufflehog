package mockaroo

import (
	"context"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mockaroo"}) + `\b([0-9a-z]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mockaroo"}
}

// FromData will find and optionally verify Mockaroo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Mockaroo,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.mockaroo.com/api/types?key=%s", resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var t typeRes
					err = json.NewDecoder(res.Body).Decode(&t)
					if err == nil && len(t.Types) > 0 {
						s1.Verified = true
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mockaroo
}

func (s Scanner) Description() string {
	return "Mockaroo is a tool for generating realistic data for testing and development. Mockaroo API keys can be used to access and generate this data."
}

type typeRes struct {
	Types []struct {
		Name       string `json:"name"`
		Type       any    `json:"type"`
		Parameters []any  `json:"parameters"`
	} `json:"types"`
}
