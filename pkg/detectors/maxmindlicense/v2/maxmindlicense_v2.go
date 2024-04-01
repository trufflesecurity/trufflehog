package maxmindlicense

import (
	"context"
	"fmt"
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
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b([0-9A-Za-z]{6}_[0-9A-Za-z]{29}_mmk)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"maxmind", "geoip"}
}

func (Scanner) Version() int { return 2 }

// FromData will find and optionally verify MaxMindLicense secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		keyRes := keyMatch[1]

		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_MaxMindLicense,
			Raw:          []byte(keyRes),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/maxmind/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			data := url.Values{}
			data.Add("license_key", keyRes)
			req, err := http.NewRequestWithContext(
				ctx, "POST", "https://secret-scanning.maxmind.com/secrets/validate-license-key",
				strings.NewReader(data.Encode()))
			if err != nil {
				r.SetVerificationError(err)
				results = append(results, r)
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			res, err := client.Do(req)
			if err != nil {
				r.SetVerificationError(err)
			}
			defer res.Body.Close()
			if err == nil && res.StatusCode >= 200 && res.StatusCode < 300 {
				r.Verified = true
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MaxMindLicense
}
