package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
	keyPat = regexp.MustCompile(`\b(sk-ant-api03-[\w\-]{93}AA)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-ant-api03"}
}

type response struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// FromData will find and optionally verify Anthropic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Anthropic,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			body := map[string]interface{}{
				"prompt": "test",
			}

			bodyBytes, err := json.Marshal(body)
			if err != nil {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/complete", bytes.NewReader(bodyBytes))
			if err != nil {
				continue
			}
			req.Header.Set("x-api-key", resMatch)
			req.Header.Set("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode == http.StatusBadRequest {
					var resp response
					if err = json.NewDecoder(res.Body).Decode(&resp); err != nil {
						err = fmt.Errorf("unexpected HTTP response body: %w", err)
						s1.SetVerificationError(err, resMatch)
						continue
					}
					if resp.Error.Message == "max_tokens_to_sample: field required" {
						// The secret is verified
						// Anthropic returns 400 on a request containing a valid API key,
						// when not containing a valid model field
						s1.Verified = true
					}
				} else if res.StatusCode == 401 {
					// The secret is determinately not verified (nothing to do)
					// Anthropic returns 401 on all requests not containing a valid x-api-key header
				} else {
					err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					s1.SetVerificationError(err, resMatch)
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Anthropic
}
