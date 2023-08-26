package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{ detectors.EndpointSetter }

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) Version() int            { return 2 }
func (Scanner) DefaultEndpoint() string { return "https://api.github.com" }

var (
	keyPat = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)
)

type userRes struct {
	Login     string `json:"login"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
	Name      string `json:"name"`
	Company   string `json:"company"`
	UserURL   string `json:"html_url"`
}

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("ghp_"), []byte("gho_"), []byte("ghu_"), []byte("ghs_"), []byte("ghr_"), []byte("github_pat_")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		token := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          token,
		}

		if verify {
			client := common.SaneHttpClient()
			for _, url := range s.Endpoints(s.DefaultEndpoint()) {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/user", string(url)), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json; charset=utf-8")
				req.Header.Add("Authorization", fmt.Sprintf("token %s", string(token)))
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						var userResponse userRes
						err = json.NewDecoder(res.Body).Decode(&userResponse)
						res.Body.Close()
						if err == nil {
							s1.Verified = true
							s1.ExtraData = map[string]string{
								"username":     userResponse.Login,
								"url":          userResponse.UserURL,
								"account_type": userResponse.Type,
								"site_admin":   fmt.Sprintf("%t", userResponse.SiteAdmin),
								"name":         userResponse.Name,
								"company":      userResponse.Company,
							}
						}
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(s1.Raw, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}
