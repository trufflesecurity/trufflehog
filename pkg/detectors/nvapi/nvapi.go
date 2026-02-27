package nvapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(nvapi-[a-zA-Z0-9_-]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"nvapi-"}
}

// FromData will find and optionally verify Nvapi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_NVAPI,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

type callerInfoResponse struct {
	Type string `json:"type"`
	User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Roles []struct {
			Org struct {
				DisplayName string `json:"displayName"`
			} `json:"org"`
			OrgRoles []string `json:"orgRoles"`
		} `json:"roles"`
	} `json:"user"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	data := url.Values{}
	data.Set("credentials", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.ngc.nvidia.com/v3/keys/get-caller-info", strings.NewReader(data.Encode()))
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var response callerInfoResponse
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return true, nil, nil
		}

		extraData := map[string]string{
			"type":       response.Type,
			"user_name":  response.User.Name,
			"user_email": response.User.Email,
		}

		// Collect distinct org display names and roles across all roles
		orgDisplayNames := make(map[string]struct{})
		orgRoles := make(map[string]struct{})

		for _, role := range response.User.Roles {
			if role.Org.DisplayName != "" {
				orgDisplayNames[role.Org.DisplayName] = struct{}{}
			}
			for _, r := range role.OrgRoles {
				orgRoles[r] = struct{}{}
			}
		}

		if len(orgDisplayNames) > 0 {
			names := make([]string, 0, len(orgDisplayNames))
			for name := range orgDisplayNames {
				names = append(names, name)
			}
			extraData["org_display_names"] = strings.Join(names, ", ")
		}

		if len(orgRoles) > 0 {
			roles := make([]string, 0, len(orgRoles))
			for role := range orgRoles {
				roles = append(roles, role)
			}
			extraData["org_roles"] = strings.Join(roles, ", ")
		}

		return true, extraData, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NVAPI
}

func (s Scanner) Description() string {
	return "NVAPI keys are used to authenticate API requests to NVIDIA's NGC API. They allow access to NVIDIA's NGC API to manage user data and perform actions on behalf of users."
}
