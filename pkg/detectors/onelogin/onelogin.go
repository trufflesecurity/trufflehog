package onelogin

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	oauthClientIDPat     = regexp.MustCompile(`(?i)id[a-zA-Z0-9_' "=]{0,20}([a-z0-9]{64})`)
	oauthClientSecretPat = regexp.MustCompile(`(?i)secret[a-zA-Z0-9_' "=]{0,20}([a-z0-9]{64})`)

	// TODO: Legacy API tokens

	apiDomains = []string{"api.us.onelogin.com", "api.eu.onelogin.com"}

	client = http.Client{Timeout: time.Second * 5}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"onelogin"}
}

// FromData will find and optionally verify Onelogin secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	for _, clientID := range oauthClientIDPat.FindAllStringSubmatch(dataStr, -1) {
		if len(clientID) != 2 {
			continue
		}
		for _, clientSecret := range oauthClientSecretPat.FindAllStringSubmatch(dataStr, -1) {
			if len(clientSecret) != 2 {
				continue
			}

			s := detectors.Result{
				DetectorType: detectorspb.DetectorType_OneLogin,
				Raw:          []byte(clientID[1]),
				RawV2:        []byte(fmt.Sprintf("%s:%s", clientID[1], clientSecret[1])),
				Redacted:     clientID[1],
			}

			if verify {
				for _, domain := range apiDomains {
					tokenURL := fmt.Sprintf("https://%s/auth/oauth2/v2/token", domain)
					req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(`{"grant_type":"client_credentials"}`))
					if err != nil {
						continue
					}
					req.Header.Add("Authorization", fmt.Sprintf("client_id:%s, client_secret:%s", clientID[1], clientSecret[1]))
					req.Header.Add("Content-Type", "application/json; charset=utf-8")
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

			results = append(results, s)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OneLogin
}
