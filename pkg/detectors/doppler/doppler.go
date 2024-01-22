package doppler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
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
	//keyPat = regexp.MustCompile(`\b(dp\.pt\.[a-zA-Z0-9]{43})\b`)
	keyPat = regexp.MustCompile(`\b(dp\.(?:ct|pt|st(?:\.[a-z0-9\-_]{2,35})?|sa|scim|audit)\.[a-zA-Z0-9]{40,44})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"dp.ct.",
		"dp.pt.",
		"dp.st",
		"dp.sa.",
		"dp.scim.",
		"dp.audit.",
	}
}

// FromData will find and optionally verify Doppler secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Doppler,
			Raw:          []byte(resMatch),
			ExtraData:    map[string]string{},
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.doppler.com/v3/me", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true

					body, err := io.ReadAll(res.Body)
					if err != nil {
						body = []byte{}
					}

					var data map[string]interface{}
					err = json.Unmarshal(body, &data)
					if err != nil {
						data = map[string]interface{}{}
					}

					keyType, ok := data["type"].(string)
					if ok {
						s1.ExtraData["key type"] = keyType
					}
					workplaceData, ok := data["workplace"].(map[string]interface{})
					if ok {
						name, ok := workplaceData["name"].(string)
						if ok {
							s1.ExtraData["workplace"] = name
						}
					}
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Doppler
}
