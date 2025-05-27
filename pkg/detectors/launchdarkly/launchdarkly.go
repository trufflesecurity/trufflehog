package launchdarkly

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func (s Scanner) getClient() *http.Client {
	if s.client == nil {
		return defaultClient
	}

	return s.client
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
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LaunchDarkly,
			Raw:          []byte(resMatch),
			ExtraData:    make(map[string]string),
		}

		if verify {
			extraData, isVerified, verificationErr := verifyLaunchDarklyKey(ctx, s.getClient(), resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
			s1.ExtraData = extraData

			// only api keys can be analyzed
			if strings.HasPrefix(resMatch, "api-") {
				s1.AnalysisInfo = map[string]string{
					"key": resMatch,
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LaunchDarkly
}

func (s Scanner) Description() string {
	return "LaunchDarkly is a feature management platform that allows teams to control the visibility of features to users. LaunchDarkly API keys can be used to access and modify feature flags and other resources within a LaunchDarkly account."
}

func verifyLaunchDarklyKey(ctx context.Context, client *http.Client, key string) (map[string]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.launchdarkly.com/api/v2/caller-identity", http.NoBody)
	if err != nil {
		return nil, false, err
	}

	req.Header.Add("Authorization", key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var callerIdentity callerIdentity
		var extraData = make(map[string]string)

		if err := json.NewDecoder(resp.Body).Decode(&callerIdentity); err != nil {
			return nil, false, err
		}

		extraData["type"] = callerIdentity.AccountId
		extraData["account"] = callerIdentity.AccountId
		extraData["environment_id"] = callerIdentity.EnvironmentId
		extraData["project_id"] = callerIdentity.ProjectId
		extraData["environment_name"] = callerIdentity.EnvironmentName
		extraData["project_name"] = callerIdentity.ProjectName
		extraData["auth_kind"] = callerIdentity.AuthKind
		extraData["token_kind"] = callerIdentity.TokenKind
		extraData["client_id"] = callerIdentity.ClientID
		extraData["token_name"] = callerIdentity.TokenName
		extraData["member_id"] = callerIdentity.MemberId
		if callerIdentity.TokenKind == "auth" {
			if callerIdentity.ServiceToken {
				extraData["token_type"] = "service"
			} else {
				extraData["token_type"] = "personal"
			}
		}

		return extraData, true, nil
	case http.StatusUnauthorized:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
