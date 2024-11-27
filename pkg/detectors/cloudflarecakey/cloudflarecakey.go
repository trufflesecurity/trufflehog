package cloudflarecakey

import (
	"context"
	"io"
	"net/http"

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

	// origin ca keys documentation: https://developers.cloudflare.com/fundamentals/api/get-started/ca-keys/
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudflare"}) + `\b(v1\.0-[A-Za-z0-9-]{171})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloudflare"}
}

// FromData will find and optionally verify CloudflareCaKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[matches[1]] = struct{}{}
	}

	for caKey := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CloudflareCaKey,
			Raw:          []byte(caKey),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/certificates?zone_id=a", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("user-agent", "curl/7.68.0") // pretend to be from curl so we do not wait 100+ seconds -> nice try did not work

			req.Header.Add("X-Auth-User-Service-Key", caKey)
			resp, err := client.Do(req)
			if err == nil {
				defer func() {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}()

				if resp.StatusCode == 200 {
					s1.Verified = true
				}
			} else {
				s1.SetVerificationError(err, caKey)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CloudflareCaKey
}

func (s Scanner) Description() string {
	return "Cloudflare is a web infrastructure and website security company. Cloudflare CA keys can be used to manage SSL/TLS certificates and other security settings."
}
