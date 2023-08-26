package twilio

import (
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
	identifierPat = regexp.MustCompile(`(?i)sid.{0,20}AC[0-9a-f]{32}`) // Should we have this? Seems restrictive.
	sidPat        = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)
	keyPat        = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
	client        = common.SaneHttpClient()
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sid")}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	identifierMatches := identifierPat.FindAll(data, -1)

	if len(identifierMatches) == 0 {
		return
	}

	keyMatches := keyPat.FindAll(data, -1)
	sidMatches := sidPat.FindAll(data, -1)

	for _, sid := range sidMatches {
		for _, key := range keyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Twilio,
				Raw:          sid,
				RawV2:        append(append([]byte(nil), sid...), key...),
				Redacted:     string(sid),
			}

			if verify {
				req, err := http.NewRequestWithContext(
					ctx, "GET", "https://verify.twilio.com/v2/Services", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Accept", "*/*")
				req.SetBasicAuth(string(sid), string(key))
				res, err := client.Do(req)
				if err == nil {
					res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(s1.Raw, detectors.DefaultFalsePositives, true) {
				continue
			}

			if len(keyMatches) > 0 {
				results = append(results, s1)
			}
		}
	}

	return detectors.CleanResults(results), nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twilio
}
