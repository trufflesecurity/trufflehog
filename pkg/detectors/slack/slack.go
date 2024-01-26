package slack

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// Check that the Slack scanner implements the SecretScanner interface at compile time.
var _ detectors.Detector = Scanner{}

var (
	defaultClient = common.SaneHttpClient()
	tokenPats     = map[string]*regexp.Regexp{
		"Slack Bot Token":               regexp.MustCompile(`xoxb\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"Slack User Token":              regexp.MustCompile(`xoxp\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"Slack Workspace Access Token":  regexp.MustCompile(`xoxa\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"Slack Workspace Refresh Token": regexp.MustCompile(`xoxr\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
	}
	verifyURL = "https://slack.com/api/auth.test"
)

type authRes struct {
	Ok     bool   `json:"ok"`
	URL    string `json:"url"`  // Workspace URL
	Team   string `json:"team"` // Human friendly workspace name
	User   string `json:"user"` // Username
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	BotID  string `json:"bot_id"`
	Error  string `json:"error"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-"}
}

// FromData will find and optionally verify Slack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	for _, tokenPat := range tokenPats {
		tokens := tokenPat.FindAllString(dataStr, -1)

		for _, token := range tokens {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Slack,
				Raw:          []byte(token),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/slack/",
			}
			if verify {
				client := s.client
				if s.client == nil {
					client = defaultClient
				}

				req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, nil)
				if err != nil {
					continue
				}

				req.Header.Add("Content-Type", "application/json; charset=utf-8")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					var authResponse authRes
					if err := json.NewDecoder(res.Body).Decode(&authResponse); err != nil {
						err = fmt.Errorf("failed to decode auth response: %w", err)
						s1.SetVerificationError(err, token)
					}

					if authResponse.Ok {
						s1.Verified = true
						// Slack API returns 200 even if the token is invalid. We need to check the error field.
					} else if authResponse.Error == "invalid_auth" {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected error auth response %+v", authResponse.Error)
						s1.SetVerificationError(err, token)
					}
				} else {
					s1.SetVerificationError(err, token)
				}
			}

			if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Slack
}
