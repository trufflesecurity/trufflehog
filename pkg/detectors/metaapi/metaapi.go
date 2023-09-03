package metaapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"metaapi", "meta-api"}) + `\b([0-9a-f]{64})\b`)
	spellPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metaapi", "meta-api"}) + `\b([0-9a-f]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("metaapi"), []byte("meta-api")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	spellMatches := spellPat.FindAllSubmatch(data, -1)

	for _, spellMatch := range spellMatches {
		if len(spellMatch) != 2 {
			continue
		}
		resSpellMatch := bytes.TrimSpace(spellMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MetaAPI,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequest("GET", fmt.Sprintf("https://api.meta-api.io/api/spells/%s/runSync", resSpellMatch), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("apikey", string(resMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					body, errBody := io.ReadAll(res.Body)

					if errBody == nil {
						if res.StatusCode >= 200 && res.StatusCode < 300 && bytes.Contains(body, []byte(`"success":true`)) {
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MetaAPI
}
