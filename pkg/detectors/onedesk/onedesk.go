package onedesk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

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
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"onedesk"}) + `\b([a-zA-Z0-9!=@#$%^]{8,64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("onedesk")}
}

// FromData will find and optionally verify Onedesk secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := emailPat.FindAllSubmatch(data, -1)
	pwordMatches := pwordPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, pwordMatch := range pwordMatches {
			if len(pwordMatch) != 2 {
				continue
			}
			resPword := bytes.TrimSpace(pwordMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Onedesk,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewBufferString(fmt.Sprintf(`{"email": "%s", "password": "%s"}`, string(resMatch), string(resPword)))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://app.onedesk.com/rest/2.0/login/loginUser", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					body := bodyBytes
					if res.StatusCode >= 200 && res.StatusCode < 300 && bytes.Contains(body, []byte(`"code":"SUCCESS"`)) {
						s1.Verified = true
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
	return detectorspb.DetectorType_Onedesk
}
