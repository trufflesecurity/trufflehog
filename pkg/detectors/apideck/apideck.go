package apideck

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
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
	keyPat = regexp.MustCompile(`\b(sk_live_[a-z0-9A-Z-]{93})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"apideck"}) + `\b([a-z0-9A-Z]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"apideck"}
}

// FromData will find and optionally verify ApiDeck secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idMatches {
			if len(idmatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ApiDeck,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://unify.apideck.com/vault/consumers", nil)
				if err != nil {
					continue
				}
				req.Header.Add("x-apideck-app-id", resIdMatch)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
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
	return detectorspb.DetectorType_ApiDeck
}
