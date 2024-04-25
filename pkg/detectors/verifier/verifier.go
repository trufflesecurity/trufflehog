package verifier

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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"verifier"}) + `\b([a-z0-9]{96})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"verifier"}) + common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"verifier"}
}

// FromData will find and optionally verify Verifier secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for emailMatch := range uniqueEmailMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Verifier,
				Raw:          []byte(resMatch),
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://verifier.meetchopra.com/verify/%s?token=%s", emailMatch, resMatch), nil)
				if err != nil {
					continue
				}
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
	return detectorspb.DetectorType_Verifier
}

func (s Scanner) Description() string {
	return "Verifier is a service used to verify the authenticity of a credential. The tokens can be used to validate user identities."
}
