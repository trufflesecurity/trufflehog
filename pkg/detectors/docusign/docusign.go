package docusign

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

type Response struct {
	AccessToken string `json:"access_token"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"integration", "id"}) + common.UUIDPattern)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + common.UUIDPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"docusign"}
}

// FromData will find and optionally verify Docusign secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resIDMatch := strings.TrimSpace(idMatch[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Docusign,
				Raw:          []byte(resIDMatch),
				Redacted:     resIDMatch,
				RawV2:        []byte(resIDMatch + resSecretMatch),
			}

			// Verify client id and secret pair by using an *undocumented* client_credentials grant type on the oauth2 endpoint.
			// If verifier breaks in the future, confirm that the oauth2 endpoint is still accepting the client_credentials grant type.
			if verify {
				req, err := http.NewRequestWithContext(ctx, "POST", "https://account-d.docusign.com/oauth/token?grant_type=client_credentials", nil)
				if err != nil {
					continue
				}

				encodedCredentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", resIDMatch, resSecretMatch)))

				req.Header.Add("Accept", "application/vnd.docusign+json; version=3")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodedCredentials))
				res, err := client.Do(req)

				if err != nil {
					return nil, errors.WrapPrefix(err, "Error making request", 0)
				}

				// Read the response body
				body, err := io.ReadAll(res.Body)

				if err != nil {
					return nil, errors.WrapPrefix(err, "Error reading response body", 0)
				}

				// Close the response body
				res.Body.Close()

				// Parse the response body into a Response struct
				var parsedResponse Response
				err = json.Unmarshal(body, &parsedResponse)
				if err != nil {
					return nil, errors.WrapPrefix(err, "Error parsing response", 0)
				}

				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 && strings.HasPrefix(parsedResponse.AccessToken, "ey") {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(resIDMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Docusign
}
