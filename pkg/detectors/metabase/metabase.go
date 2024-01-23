package metabase

import (
	"context"
	"encoding/json"
	regexp "github.com/wasilibs/go-re2"
	"io"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b([a-zA-Z0-9-]{36})\b`)

	baseURL = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b(https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{7,256})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metabase"}
}

// FromData will find and optionally verify Metabase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := baseURL.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			if len(urlMatch) != 2 {
				continue
			}
			resURLMatch := strings.TrimSpace(urlMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Metabase,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resURLMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, resURLMatch+"/api/user/current", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Metabase-Session", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					body, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					if res.StatusCode == http.StatusOK && json.Valid(body) {
						s1.Verified = true
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Metabase
}
