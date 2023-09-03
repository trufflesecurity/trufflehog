package onelogin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the detector interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	oauthClientIDPat     = regexp.MustCompile(`(?i)id[a-zA-Z0-9_' "=]{0,20}([a-z0-9]{64})`)
	oauthClientSecretPat = regexp.MustCompile(`(?i)secret[a-zA-Z0-9_' "=]{0,20}([a-z0-9]{64})`)

	apiDomains = [][]byte{[]byte("api.us.onelogin.com"), []byte("api.eu.onelogin.com")}

	client = http.Client{Timeout: time.Second * 5}
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("onelogin")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idSubMatches := oauthClientIDPat.FindAllSubmatch(data, -1)
	secretSubMatches := oauthClientSecretPat.FindAllSubmatch(data, -1)

	for _, idMatch := range idSubMatches {
		if len(idMatch) != 2 {
			continue
		}
		for _, secretMatch := range secretSubMatches {
			if len(secretMatch) != 2 {
				continue
			}

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_OneLogin,
				Raw:          bytes.TrimSpace(idMatch[1]),
				RawV2:        bytes.TrimSpace(secretMatch[1]),
				Redacted:     string(idMatch[1]),
			}

			if verify {
				for _, domain := range apiDomains {
					tokenURL := fmt.Sprintf("https://%s/auth/oauth2/v2/token", domain)
					req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBuffer([]byte(`{"grant_type":"client_credentials"}`)))
					if err != nil {
						continue
					}
					req.Header.Add("Authorization", fmt.Sprintf("client_id:%s, client_secret:%s", idMatch[1], secretMatch[1]))
					req.Header.Add("Content-Type", "application/json; charset=utf-8")
					res, err := client.Do(req)
					if err == nil {
						res.Body.Close()

						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s.Verified = true
						}
					}
				}
			}

			if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OneLogin
}
