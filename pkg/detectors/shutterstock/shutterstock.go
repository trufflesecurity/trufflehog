package shutterstock

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"shutterstock"}) + `\b([0-9a-zA-Z]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"shutterstock"}) + `\b([0-9a-zA-Z]{16})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"shutterstock"}
}

// FromData will find and optionally verify Shutterstock secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Shutterstock,
				Raw:          []byte(resSecretMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.shutterstock.com/v2/images/search", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Accept", "application/json")
				req.SetBasicAuth(resMatch, resSecretMatch)
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
	return detectorspb.DetectorType_Shutterstock
}

func (s Scanner) Description() string {
	return "Shutterstock is a global provider of stock photography, footage, music, and editing tools. Shutterstock API keys can be used to access and modify this content."
}
