package rownd

import (
	"context"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{48})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([0-9]{18})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rownd"}
}

// FromData will find and optionally verify Rownd secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resId := strings.TrimSpace(idMatch[1])

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}
			keyMatch := strings.TrimSpace(match[1])

			for _, secret := range secretMatches {
				if len(secret) != 2 {
					continue
				}

				secretMatch := strings.TrimSpace(secret[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Rownd,
					Raw:          []byte(keyMatch),
					RawV2:        []byte(keyMatch + secretMatch),
				}

				if verify {

					req, err := http.NewRequestWithContext(ctx, "GET", "https://api.rownd.io/applications/"+resId+"/users/data", nil)
					if err != nil {
						continue
					}
					req.Header.Add("x-rownd-app-key", keyMatch)
					req.Header.Add("x-rownd-app-secret", secretMatch)
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(keyMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Rownd
}
