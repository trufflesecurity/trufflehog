package sendbirdorganizationapi

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sendbird"}) + `\b([0-9a-f]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sendbird"}
}

// FromData will find and optionally verify SendbirdOrganizationAPI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SendbirdOrganizationAPI,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			req, err := http.NewRequestWithContext(ctx, "GET", "https://gate.sendbird.com/api/v2/applications", nil)
			if err != nil {
				s1.SetVerificationError(err, resMatch)
			}
			req.Header.Add("SENDBIRDORGANIZATIONAPITOKEN", resMatch)
			res, err := client.Do(req)
			if err != nil {
				s1.SetVerificationError(err, resMatch)
			} else {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else if res.StatusCode != http.StatusForbidden {
					err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					s1.SetVerificationError(err, resMatch)
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SendbirdOrganizationAPI
}
