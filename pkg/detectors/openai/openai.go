package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"T3BlbkFJ"}) + `(\bsk-[[:alnum:]]{20}T3BlbkFJ[[:alnum:]]{20}\b)`)

type orgResponse struct {
	Data []organization `json:"data"`
}

type organization struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	User        string `json:"name"`
	Description string `json:"description"`
	Personal    bool   `json:"personal"`
	Default     bool   `json:"is_default"`
	Role        string `json:"role"`
}

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("T3BlbkFJ")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		token := bytes.TrimSpace(match[1])

		redacted := append(append(token[:3], []byte("...")...), token[47:]...)

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenAI,
			Redacted:     string(redacted),
			Raw:          token,
		}

		if verify {
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/organizations", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json; charset=utf-8")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(token)))

			res, err := client.Do(req)

			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var orgs orgResponse
					err = json.NewDecoder(res.Body).Decode(&orgs)
					if err == nil {
						s1.Verified = true
						org := orgs.Data[0]
						s1.ExtraData = map[string]string{
							"id":          org.ID,
							"title":       org.Title,
							"user":        org.User,
							"description": org.Description,
							"role":        org.Role,
							"is_personal": strconv.FormatBool(org.Personal),
							"is_default":  strconv.FormatBool(org.Default),
							"total_orgs":  fmt.Sprintf("%d", len(orgs.Data)),
						}
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenAI
}
