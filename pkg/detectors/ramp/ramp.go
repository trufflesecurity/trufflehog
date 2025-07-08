package ramp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(`\b(ramp_id_[[:alnum:]]{40})\b`)
	secretPat = regexp.MustCompile(`\b(ramp_sec_[[:alnum:]]{48})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ramp_"}
}

// FromData will find and optionally verify Ramp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {

		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {

			resSecret := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Ramp,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + ":" + resSecret),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				body := url.Values{
					"grant_type": {"client_credentials"},
					"scope":      {"user:read"},
				}

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.ramp.com/developer/v1/token", strings.NewReader(body.Encode()))
				if err != nil {
					continue
				}
				req.SetBasicAuth(resMatch, resSecret)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Ramp
}

func (s Scanner) Description() string {
	return "Ramp provides financial services including expense management and corporate cards. Ramp credentials can be used to access and manage these financial services."
}
