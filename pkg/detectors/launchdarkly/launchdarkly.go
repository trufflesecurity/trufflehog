package launchdarkly

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Launchdarkly keys are UUIDv4s with either api- or sdk- prefixes.
	// mob- keys are possible, but are not sensitive credentials.
	keyPat = regexp.MustCompile(`\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

type callerIdentity struct {
	AccountId       string `json:"accountId,omitempty"`
	EnvironmentId   string `json:"environmentId,omitempty"`
	ProjectId       string `json:"projectId,omitempty"`
	EnvironmentName string `json:"environmentName,omitempty"`
	ProjectName     string `json:"projectName,omitempty"`
	AuthKind        string `json:"authKind,omitempty"`
	TokenKind       string `json:"tokenKind,omitempty"`
	ClientID        string `json:"clientId,omitempty"`
	TokenName       string `json:"tokenName,omitempty"`
	TokenId         string `json:"tokenId,omitempty"`
	MemberId        string `json:"memberId,omitempty"`
	ServiceToken    bool   `json:"serviceToken"`
}

// We are not including "mob-" because client keys are not sensitive.
// They are expected to be public.
func (s Scanner) Keywords() []string {
	return []string{"api-", "sdk-"}
}

// FromData will find and optionally verify LaunchDarkly secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LaunchDarkly,
			Raw:          []byte(resMatch),
			ExtraData:    make(map[string]string),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://app.launchdarkly.com/api/v2/caller-identity", nil)
			if err != nil {
				continue
			}
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req.Header.Add("Authorization", resMatch)
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
					var callerIdentity callerIdentity
					if err := json.NewDecoder(res.Body).Decode(&callerIdentity); err == nil { // no error in parsing
						s1.ExtraData["type"] = callerIdentity.TokenKind
						s1.ExtraData["account_id"] = callerIdentity.AccountId
						s1.ExtraData["environment_id"] = callerIdentity.EnvironmentId
						s1.ExtraData["project_id"] = callerIdentity.ProjectId
						s1.ExtraData["environment_name"] = callerIdentity.EnvironmentName
						s1.ExtraData["project_name"] = callerIdentity.ProjectName
						s1.ExtraData["auth_kind"] = callerIdentity.AuthKind
						s1.ExtraData["token_kind"] = callerIdentity.TokenKind
						s1.ExtraData["client_id"] = callerIdentity.ClientID
						s1.ExtraData["token_name"] = callerIdentity.TokenName
						s1.ExtraData["member_id"] = callerIdentity.MemberId
						if callerIdentity.TokenKind == "auth" {
							if callerIdentity.ServiceToken {
								s1.ExtraData["token_type"] = "service"
							} else {
								s1.ExtraData["token_type"] = "personal"
							}
						}
					}
				} else if res.StatusCode == 401 {
					// 401 is expected for an invalid token, so there is nothing to do here.
				} else {
					err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					s1.SetVerificationError(err, resMatch)
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LaunchDarkly
}
