package zoom

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zoom"}) + `\b([0-9a-zA-Z]{23}_[0-9a-zA-Z]{8})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"zoom"}) + `\b(C[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zoom"}
}

// FromData will find and optionally verify Zoom secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			id := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Zoom,
				Raw:          []byte(resMatch),
			}

			if verify {
				data := id + ":" + resMatch

				sEnc := b64.StdEncoding.EncodeToString([]byte(data))

				query_params := "?grant_type=authorization_code&code=362ad374-735c-4f69-aa8e-bf384f8602de&redirect_uri=http%3A%2F%2Flocalhost.com%3A3000%2Fzoom"

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.zoom.us/oauth/token"+query_params, nil)

				if err != nil {
					continue
				}

				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))

				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				client := common.SaneHttpClient()
				res, err := client.Do(req)

				if err == nil {
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

			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Zoom
}
