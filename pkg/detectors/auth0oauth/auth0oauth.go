package auth0oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	clientIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"auth0"}) + `\b([a-zA-Z0-9_-]{32,60})\b`)
	clientSecretPat = regexp.MustCompile(`\b([a-zA-Z0-9_-]{64,})\b`)
	domainPat       = regexp.MustCompile(`\b([a-zA-Z0-9][a-zA-Z0-9._-]*auth0\.com)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("auth0")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	clientIdMatches := clientIdPat.FindAllSubmatch(data, -1)
	clientSecretMatches := clientSecretPat.FindAllSubmatch(data, -1)
	domainMatches := domainPat.FindAllSubmatch(data, -1)

	for _, clientIdMatch := range clientIdMatches {
		if len(clientIdMatch) != 2 {
			continue
		}
		clientIdRes := bytes.TrimSpace(clientIdMatch[1])

		for _, clientSecretMatch := range clientSecretMatches {
			if len(clientSecretMatch) != 2 {
				continue
			}
			clientSecretRes := bytes.TrimSpace(clientSecretMatch[1])

			for _, domainMatch := range domainMatches {
				if len(domainMatch) != 2 {
					continue
				}
				domainRes := bytes.TrimSpace(domainMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Auth0oauth,
					Redacted:     string(clientIdRes),
					Raw:          clientSecretRes,
					RawV2:        append(clientIdRes, clientSecretRes...),
				}

				if verify {

					data := url.Values{}
					data.Set("grant_type", "authorization_code")
					data.Set("client_id", string(clientIdRes))
					data.Set("client_secret", string(clientSecretRes))
					data.Set("code", "AUTHORIZATION_CODE")
					data.Set("redirect_uri", "undefined")

					req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+string(domainRes)+"/oauth/token", strings.NewReader(data.Encode()))
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						bodyBytes, err := io.ReadAll(res.Body)
						if err != nil {
							continue
						}
						body := string(bodyBytes)

						if !bytes.Contains(bodyBytes, []byte("access_denied")) {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(clientIdRes, detectors.DefaultFalsePositives, true) {
								continue
							}
						}

					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Auth0oauth
}
