package liveagent

import (
	"context"
	"encoding/json"
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
	domainPat = regexp.MustCompile(`\b(https?://[A-Za-z0-9-]+\.ladesk\.com)\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"liveagent", "apikey"}) + `\b([a-zA-Z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"liveagent", "ladesk"}
}

type response struct {
	Message string `json:"message"`
}

// FromData will find and optionally verify LiveAgent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := strings.TrimSpace(match[1])

		for _, domainMatch := range domainMatches {
			if len(domainMatch) != 2 {
				continue
			}
			domainRes := strings.TrimSpace(domainMatch[0])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_LiveAgent,
				Raw:          []byte(resMatch),
				ExtraData: map[string]string{
					"domain": domainRes,
				},
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", domainRes+"/api/v3/agents", nil)
				if err != nil {
					continue
				}
				req.Header.Add("apikey", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 403 {
						var r response
						if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
							s1.SetVerificationError(err, resMatch)
							continue
						}

						// If the message is "You do not have sufficient privileges", then the key is valid, but does not have access to the `/agents` endpoint.
						if r.Message == "You do not have sufficient privileges" {
							s1.Verified = true
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LiveAgent
}
