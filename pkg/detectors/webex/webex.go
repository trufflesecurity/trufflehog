package webex

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"webex"}) + `\b([a-f0-9]{64})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"webex"}) + `\b(C[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"webex"}
}

// FromData will find and optionally verify Webex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {

			if len(idMatch) != 2 {
				continue
			}
			id := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Webex,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader("grant_type=authorization_code&code=362ad374-735c-4f69-aa8e-bf384f8602de&client_id=" + id + "&client_secret=" + resMatch + "&redirect_uri=http%3A%2F%2Flocalhost.com%2Fb")
				req, err := http.NewRequestWithContext(ctx, "POST", "https://webexapis.com/v1/access_token", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				client := common.SaneHttpClient()
				res, err := client.Do(req)
				if err == nil {
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					if err == nil {
						var message struct {
							Message string `json:"message"`
						}
						if err := json.Unmarshal(body, &message); err == nil {
							var getError = regexp.MustCompile(detectors.PrefixRegex([]string{"error"}) + `(redirect_uri_mismatch)`)
							result := getError.FindAllStringSubmatch(message.Message, -1)
							if len(result) > 0 {
								s1.Verified = true
							}
						}
					}
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Webex
}
