package twilio

import (
	"context"
	"net/http"
	"net/url"
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
	identifierPat = regexp.MustCompile(`(?i)sid.{0,20}AC[0-9a-f]{32}`) // Should we have this? Seems restrictive.
	sidPat        = regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)
	keyPat        = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sid"}
}

// FromData will find and optionally verify Twilio secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	identifierMatches := identifierPat.FindAllString(dataStr, -1)

	if len(identifierMatches) == 0 {
		return
	}

	keyMatches := keyPat.FindAllString(dataStr, -1)
	sidMatches := sidPat.FindAllString(dataStr, -1)

	for _, sid := range sidMatches {

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Twilio,
			Raw:          []byte(sid),
			Redacted:     sid,
		}

		if verify {
			client := common.SaneHttpClient()
			for _, key := range keyMatches {

				form := url.Values{}
				form.Add("FriendlyName", "MyServiceName")
				req, err := http.NewRequestWithContext(
					ctx, "POST", "https://verify.twilio.com/v2/Services",

					strings.NewReader(form.Encode()),
				)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Accept", "*/*")
				req.SetBasicAuth(sid, key)
				res, err := client.Do(req)
				if err == nil {
					res.Body.Close() // The request body is unused.

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s.Verified = true
					}
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		if len(keyMatches) > 0 {
			results = append(results, s)
		}
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twilio
}
