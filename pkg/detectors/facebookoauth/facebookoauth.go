package facebookoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	apiIdPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"facebook"}) + `\b([0-9]{15,18})\b`) // not actually sure of the upper bound
	apiSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"facebook"}) + `\b([A-Za-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"facebook"}
}

// FromData will find and optionally verify FacebookOAuth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiIdMatches := apiIdPat.FindAllStringSubmatch(dataStr, -1)
	apiSecretMatches := apiSecretPat.FindAllStringSubmatch(dataStr, -1)

	for _, apiIdMatch := range apiIdMatches {
		apiIdRes := strings.TrimSpace(apiIdMatch[1])

		for _, apiSecretMatch := range apiSecretMatches {
			apiSecretRes := strings.TrimSpace(apiSecretMatch[1])

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_FacebookOAuth,
				Redacted:     apiIdRes,
				Raw:          []byte(apiSecretRes),
				SecretParts: map[string]string{
					"id":     apiIdRes,
					"secret": apiSecretRes,
				},
				RawV2: []byte(apiIdRes + apiSecretRes),
			}

			if verify {
				isVerified, extraData, verificationErr := verifyFacebookOAuth(ctx, apiIdRes, apiSecretRes)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, apiSecretRes)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}


// We query /{app-id}?fields=roles, the documented way to validate an app ID/secret
// pair (https://stackoverflow.com/questions/15621471/validate-a-facebook-app-id-and-app-secret):
// valid credentials return 200 with the app's roles, while an invalid pair returns a
// 400 OAuthException (code 190, "Invalid OAuth access token signature.").

func verifyFacebookOAuth(ctx context.Context, appID, appSecret string) (bool, map[string]string, error) {
	url := fmt.Sprintf("https://graph.facebook.com/%s?fields=roles&access_token=%s|%s", appID, appID, appSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, err
	}

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
		var r rolesResponse
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			// The credentials are valid (200), so report verified even if we can't
			// parse the optional roles context.
			return true, nil, nil
		}
		return true, r.extraData(), nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		// Invalid app ID/secret pair (e.g. OAuthException code 190).
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

// rolesResponse models the /{app-id}?fields=roles payload.
type rolesResponse struct {
	Roles struct {
		Data []struct {
			User string `json:"user"`
			Role string `json:"role"`
		} `json:"data"`
	} `json:"roles"`
}

// extraData flattens the app roles into result ExtraData: a count plus a
// comma-separated list of "user:role" pairs identifying who has access to the app.
func (r rolesResponse) extraData() map[string]string {
	data := r.Roles.Data
	if len(data) == 0 {
		return nil
	}

	pairs := make([]string, 0, len(data))
	for _, role := range data {
		pairs = append(pairs, role.User+":"+role.Role)
	}

	return map[string]string{
		"app_roles_count": strconv.Itoa(len(data)),
		"app_roles":       strings.Join(pairs, ", "),
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_FacebookOAuth
}

func (s Scanner) Description() string {
	return "Facebook OAuth tokens are used to authenticate users and provide access to Facebook's API services."
}
