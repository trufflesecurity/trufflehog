package codeclimate

import (
	"context"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"codeclimate"}) + `\b([a-f0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"codeclimate"}
}

type response struct {
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

// FromData will find and optionally verify Codeclimate secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Codeclimate,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.codeclimate.com/v1/user", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.api+json")
			req.Header.Add("Authorization", fmt.Sprintf("Token token=%s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var r response
					if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
						s1.SetVerificationError(err, resMatch)
						continue
					}
					if r.Data.Id != "" {
						s1.Verified = true
					}
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key
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
	return detectorspb.DetectorType_Codeclimate
}
