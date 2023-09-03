package dotmailer

import (
	"bytes"
	"context"
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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"dotmailer"}) + `\b(apiuser-[a-z0-9]{12}@apiconnector.com)\b`)
	passPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dotmailer"}) + `\b([a-zA-Z0-9\S]{8,24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("dotmailer")}
}

// FromData will find and optionally verify Dotmailer secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	passMatches := passPat.FindAllSubmatch(data, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, passMatch := range passMatches {
			if len(passMatch) != 2 {
				continue
			}

			resPassMatch := bytes.TrimSpace(passMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dotmailer,
				Raw:          resMatch,
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://r3-api.dotmailer.com/v2/account-info", nil)
				if err != nil {
					continue
				}

				req.SetBasicAuth(string(resMatch), string(resPassMatch))
				res, err := client.Do(req)
				if err != nil {
					continue
				}
				defer res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					if detectors.IsKnownFalsePositive([]byte(resPassMatch), detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dotmailer
}
