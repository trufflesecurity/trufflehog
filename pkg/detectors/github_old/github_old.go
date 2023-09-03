package github_old

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{ detectors.EndpointSetter }

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) Version() int            { return 1 }
func (Scanner) DefaultEndpoint() string { return "https://api.github.com" }

var (
	keyPat = regexp.MustCompile(`(?i)(?:github|gh|pat)[^\.].{0,40}[ =:'"]+([a-f0-9]{40})\b`)
)

type userRes struct {
	Login     string `json:"login"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
	Name      string `json:"name"`
	Company   string `json:"company"`
}

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("github"), []byte("gh"), []byte("pat")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		token := match[1]

		specificFPs := []detectors.FalsePositive{[]byte("github commit")}
		if detectors.IsKnownFalsePositive(token, specificFPs, false) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          token,
		}

		if verify {
			client := common.SaneHttpClient()
			for _, url := range s.Endpoints(s.DefaultEndpoint()) {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/user", url), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json; charset=utf-8")
				req.Header.Add("Authorization", fmt.Sprintf("token %s", string(token)))
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}
