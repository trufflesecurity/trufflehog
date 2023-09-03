package shopify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client    = common.SaneHttpClient()
	keyPat    = regexp.MustCompile(`\b(shppa_|shpat_)([0-9A-Fa-f]{32})\b`)
	domainPat = regexp.MustCompile(`[a-zA-Z0-9-]+\.myshopify\.com`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("shppa_"), []byte("shpat_")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAll(data, -1)
	domainMatches := domainPat.FindAll(data, -1)

	for _, key := range keyMatches {
		key = bytes.TrimSpace(key)

		for _, domain := range domainMatches {
			domain = bytes.TrimSpace(domain)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Shopify,
				Redacted:     string(domain),
				Raw:          append(key, domain...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+string(domain)+"/admin/oauth/access_scopes.json", nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Shopify-Access-Token", string(key))
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						shopifyTokenAccessScopes := shopifyTokenAccessScopes{}
						err := json.NewDecoder(res.Body).Decode(&shopifyTokenAccessScopes)
						if err == nil {
							var handleArray []string
							for _, handle := range shopifyTokenAccessScopes.AccessScopes {
								handleArray = append(handleArray, handle.Handle)
							}
							s1.Verified = true
							s1.ExtraData = map[string]string{
								"access_scopes": strings.Join(handleArray, ","),
							}
						}
						res.Body.Close()
					}
				} else {
					if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
			results = append(results, s1)
		}
	}
	return results, nil
}

type shopifyTokenAccessScopes struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shopify
}
