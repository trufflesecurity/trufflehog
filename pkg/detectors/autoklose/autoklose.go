package autoklose

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"autoklose"}) + `\b([a-zA-Z0-9-]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"autoklose"}
}

// FromData will find and optionally verify Autoklose secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Autoklose,
			Raw:          []byte(resMatch),
		}

		if verify {
			// API Documentation: https://api.aklab.xyz/#auth-info-fd71acd1-2e41-4991-8789-3edfd258479a
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.autoklose.com/api/me/?api_token=%s", resMatch), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer func() {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}()

				if res.StatusCode == http.StatusOK {
					s1.Verified = true
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}

					var responseBody map[string]interface{}
					if err := json.Unmarshal(bodyBytes, &responseBody); err == nil {
						if email, ok := responseBody["email"].(string); ok {
							s1.ExtraData = map[string]string{
								"email": email,
							}
						}
					}
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Autoklose
}

func (s Scanner) Description() string {
	return "Autoklose is a sales automation tool that allows users to streamline their email outreach and follow-up processes. Autoklose API tokens can be used to access and manage campaigns, contacts, and other related data."
}
