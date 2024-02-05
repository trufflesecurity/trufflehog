package squareapp

import (
	"bytes"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// possibly always `sq0csp` for secret
	// and `sq0idb` for app
	keyPat = regexp.MustCompile(`[\w\-]*sq0i[a-z]{2}-[0-9A-Za-z\-_]{22,43}`)
	secPat = regexp.MustCompile(`[\w\-]*sq0c[a-z]{2}-[0-9A-Za-z\-_]{40,50}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sq0i"}
}

// FromData will find and optionally verify SquareApp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllString(dataStr, -1)
	secMatches := secPat.FindAllString(dataStr, -1)
	for _, match := range matches {
		for _, secMatch := range secMatches {

			if detectors.IsKnownFalsePositive(strings.ToLower(secMatch), detectors.DefaultFalsePositives, true) {
				continue
			}

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_SquareApp,
				Raw:          []byte(match),
				Redacted:     match,
			}

			if verify {
				baseURL := "https://connect.squareupsandbox.com/oauth2/revoke"

				client := common.SaneHttpClient()
				reqData, err := json.Marshal(map[string]string{
					"client_id":    match,
					"access_token": "fakeTruffleHogAccessTokenForVerification",
				})
				if err != nil {
					return results, err
				}

				req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewReader(reqData))
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Client %s", secMatch))
				req.Header.Add("Content-Type", "application/json")

				// unclear if this version needs to be set or matters, seems to work without, but docs want it
				// req.Header.Add("Square-Version", "2020-08-12")
				res, err := client.Do(req)
				if err == nil {
					res.Body.Close() // The request body is unused.

					// 404 = Correct credentials. The fake access token should not be found.
					if res.StatusCode == http.StatusNotFound {
						s.Verified = true
					}
				}
			}

			if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s)
		}
	}
	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SquareApp
}
