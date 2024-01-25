package twilio

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
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
		for _, key := range keyMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Twilio,
				Raw:          []byte(sid),
				RawV2:        []byte(sid + key),
				Redacted:     sid,
			}

			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/twilio/",
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				req, err := http.NewRequestWithContext(
					ctx, "GET", "https://verify.twilio.com/v2/Services", nil)
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
						s1.Verified = true
					} else if res.StatusCode == 401 || res.StatusCode == 403 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, key)
					}
				} else {
					s1.SetVerificationError(err, key)
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
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
