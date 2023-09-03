package fastlypersonaltoken

import (
	"bytes"
	"context"
	"encoding/json"
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
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fastly"}) + `\b([A-Za-z0-9_-]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("fastly")}
}

type fastlyUserRes struct {
	Login                string `json:"login"`
	Name                 string `json:"name"`
	Role                 string `json:"role"`
	TwoFactorAuthEnabled bool   `json:"two_factor_auth_enabled"`
	Locked               bool   `json:"locked"`
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FastlyPersonalToken,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fastly.com/current_user", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Fastly-Key", string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var userRes fastlyUserRes
					err = json.Unmarshal(bodyBytes, &userRes)
					if err != nil {
						continue
					}
					s1.Verified = true
					s1.ExtraData = map[string]string{
						"username":                userRes.Login,
						"name":                    userRes.Name,
						"role":                    userRes.Role,
						"locked":                  fmt.Sprintf("%t", userRes.Locked),
						"two_factor_auth_enabled": fmt.Sprintf("%t", userRes.TwoFactorAuthEnabled),
					}
				} else {
					if detectors.IsKnownFalsePositive([]byte(resMatch), detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FastlyPersonalToken
}
