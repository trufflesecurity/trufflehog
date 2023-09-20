package microsoftteamswebhook

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

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
	defaultClient = common.SaneHttpClientTimeOut(5 * time.Second)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`(https:\/\/[a-zA-Z-0-9]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\@[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\/IncomingWebhook\/[a-zA-Z-0-9]{32}\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"webhook.office.com"}
}

// FromData will find and optionally verify MicrosoftTeamsWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MicrosoftTeamsWebhook,
			Raw:          []byte(resMatch),
		}
		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			payload := strings.NewReader(`{'text':''}`)
			req, err := http.NewRequestWithContext(ctx, "POST", resMatch, payload)
			if err != nil {
				s1.VerificationError = err
			} else {
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err != nil {
					s1.VerificationError = err
				} else {
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					if err != nil {
						s1.VerificationError = err
					} else if res.StatusCode == http.StatusBadRequest {
						if strings.Contains(string(body), "Text is required") {
							s1.Verified = true
						} else {
							s1.VerificationError = fmt.Errorf("unexpected response body: %s", string(body))
						}
					} else if res.StatusCode < 200 || res.StatusCode >= 500 {
						s1.VerificationError = fmt.Errorf("unexpected HTTP response status: %d", res.StatusCode)
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, false) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MicrosoftTeamsWebhook
}
