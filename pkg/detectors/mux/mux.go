package mux

import (
	"context"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"mux"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mux"}) + `([ \r\n]{0,1}[0-9A-Za-z\/\+]{75}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mux"}
}

// FromData will find and optionally verify Mux secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Mux,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.mux.com/video/v1/assets", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.SetBasicAuth(resMatch, resSecretMatch)
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key":    resMatch,
						"secret": resSecretMatch,
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mux
}

func (s Scanner) Description() string {
	return "Mux is a video streaming service that provides APIs for video hosting, live streaming, and video analytics. Mux API keys can be used to access and manage video assets and streaming data."
}
