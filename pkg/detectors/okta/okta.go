package okta

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	domainPat = regexp.MustCompile(`\b[a-z0-9-]{1,40}\.okta(?:preview|-emea){0,1}\.com\b`)
	tokenPat  = regexp.MustCompile(`\b00[a-zA-Z0-9_-]{40}\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("okta")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, tokenMatch := range tokenPat.FindAll(data, -1) {
		for _, domainMatch := range domainPat.FindAll(data, -1) {
			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_Okta,
				Raw:          tokenMatch,
				RawV2:        []byte(fmt.Sprintf("%s:%s", string(domainMatch), string(tokenMatch))),
			}

			if verify {
				url := fmt.Sprintf("https://%s/api/v1/users/me", string(domainMatch))
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return results, err
				}
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("SSWS %s", string(tokenMatch)))

				resp, err := common.SaneHttpClient().Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					body, _ := io.ReadAll(resp.Body)
					if bytes.Contains(body, []byte("activated")) {
						s.Verified = true
					}
				}
			}

			if !s.Verified {
				if detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
					continue
				}
			}

			results = append(results, s)
		}
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Okta
}
