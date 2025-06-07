package unifyid

import (
	"context"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"unify"}) + `\b([0-9A-Za-z_=-]{44})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"unify"}
}

// FromData will find and optionally verify Unifyid secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_UnifyID,
			Raw:          []byte(resMatch),
		}

		if verify {
			payload := strings.NewReader(`{"token": "sample"}`)
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api.unify.id/v1/humandetect/verify", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("X-API-Key", resMatch)
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)
				if (res.StatusCode >= 200 && res.StatusCode < 300) || (res.StatusCode == 400 && strings.Contains(body, "invalid token")) {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_UnifyID
}

func (s Scanner) Description() string {
	return "UnifyID provides human detection services. These API keys can be used to verify human presence."
}
