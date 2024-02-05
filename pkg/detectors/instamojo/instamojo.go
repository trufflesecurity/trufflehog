package instamojo

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	// KeyPat is client_id
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"instamojo"}) + `\b([0-9a-zA-Z]{40})\b`)
	// Secretpat is Client_secret
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"instamojo"}) + `\b([0-9a-zA-Z]{128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"instamojo"}
}

// FromData will find and optionally verify Instamojo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	clientIdmatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range secretMatches {
		if len(match) != 2 {
			continue
		}
		resSecret := strings.TrimSpace(match[1])

		for _, clientIdMatch := range clientIdmatches {
			if len(clientIdMatch) != 2 {
				continue
			}
			resClientId := strings.TrimSpace(clientIdMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Instamojo,
				Raw:          []byte(resClientId),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				payload := strings.NewReader("grant_type=client_credentials&client_id=" + resClientId + "&client_secret=" + resSecret)

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.instamojo.com/oauth2/token/", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					body := string(bodyBytes)
					if (res.StatusCode >= 200 && res.StatusCode < 300) && strings.Contains(body, "access_token") {
						s1.Verified = true
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resSecret)
					}
				} else {
					s1.SetVerificationError(err, resSecret)
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Instamojo
}
