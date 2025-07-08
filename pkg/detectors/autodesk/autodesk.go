package autodesk

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"autodesk"}) + `\b([0-9A-Za-z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"autodesk"}) + `\b([0-9A-Za-z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"autodesk"}
}

// FromData will find and optionally verify Autodesk secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, secretMatch := range secretMatches {
			resSecret := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Autodesk,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecret),
			}

			if verify {
				payload := strings.NewReader(fmt.Sprintf(`grant_type=client_credentials&client_id=%s&client_secret=%s`, resMatch, resSecret))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://developer.api.autodesk.com/authentication/v1/authenticate", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Autodesk
}

func (s Scanner) Description() string {
	return "Autodesk provides software services for design and engineering. Autodesk API keys can be used to access and modify data within Autodesk services."
}
