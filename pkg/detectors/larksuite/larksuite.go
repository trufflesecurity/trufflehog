package larksuite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Check that the LarkSuite scanner implements the SecretScanner interface at compile time.
var _ detectors.Detector = Scanner{}

type tokenType string

const (
	TenantAccessToken tokenType = "Tenant Access Token"
	UserAccessToken   tokenType = "User Access Token"
	AppAccessToken    tokenType = "App Access Token"
)

var (
	defaultClient = common.SaneHttpClient()
	tokenPats     = map[tokenType]*regexp.Regexp{
		TenantAccessToken: regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "tenant"}) + `(?:^|[^-])\b(t-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
		UserAccessToken:   regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "user"}) + `(?:^|[^-])\b(u-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
		AppAccessToken:    regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "app"}) + `(?:^|[^-])\b(a-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
	}

	verificationUrls = map[tokenType]string{
		TenantAccessToken: "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
		UserAccessToken:   "https://open.larksuite.com/open-apis/authen/v1/user_info",
		AppAccessToken:    "https://open.larksuite.com/open-apis/calendar/v4/calendars",
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lark", "larksuite"}
}

// FromData will find and optionally verify Larksuite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	for key, tokenPat := range tokenPats {
		uniqueMatches := make(map[string]struct{})
		for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
			uniqueMatches[match[1]] = struct{}{}
		}

		for token := range uniqueMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_LarkSuite,
				Raw:          []byte(token),
			}
			s1.ExtraData = map[string]string{
				"token_type": string(key),
			}
			if verify {
				client := s.client
				if s.client == nil {
					client = defaultClient
				}

				var (
					isVerified bool
					err        error
				)

				isVerified, err = verifyAccessToken(ctx, client, verificationUrls[key], token)
				s1.Verified = isVerified
				s1.SetVerificationError(err, token)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LarkSuite
}

func (s Scanner) Description() string {
	return "LarkSuite is a collaborative suite that includes chat, calendar, and cloud storage features. The detected token can be used to access and interact with these services."
}

func verifyAccessToken(ctx context.Context, client *http.Client, url string, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	switch res.StatusCode {
	case http.StatusOK, http.StatusBadRequest:
		var bodyResponse verificationResponse
		if err := json.NewDecoder(res.Body).Decode(&bodyResponse); err != nil {
			err = fmt.Errorf("failed to decode response: %w", err)
			return false, err
		} else {
			if bodyResponse.Code == 0 || bodyResponse.Code == 99991672 {
				return true, nil
			} else {
				return false, fmt.Errorf("unexpected verification response code %d, message %s", bodyResponse.Code, bodyResponse.Message)
			}
		}
	default:
		// 500 larksuite was unable to generate a result
		return false, err
	}
}

type verificationResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}
