package moderation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"moderation"}) + `\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{115}\.[a-zA-Z0-9_]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"moderation"}
}

// FromData will find and optionally verify Moderation secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Moderation,
			Raw:          []byte(resMatch),
		}

		if verify {
			timeout := 5 * time.Second
			client.Timeout = timeout
			payload := strings.NewReader(`{"value": "This is an english text"}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://moderationapi.com/api/v1/analyze/language", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			req.Header.Add("Content-type", "application/json")
			res, err := client.Do(req)

			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Moderation
}

func (s Scanner) Description() string {
	return "Moderation API keys are used to access the Moderation API, which provides services for analyzing and moderating content."
}
