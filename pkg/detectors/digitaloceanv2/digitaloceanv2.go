package digitaloceanv2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	lwa "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lightweight_analyze"
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
	keyPat = regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dop_v1_", "doo_v1_", "dor_v1_"}
}

// FromData will find and optionally verify DigitalOceanV2 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logCtx := logContext.AddLogger(ctx)
	dataStr := string(data)

	var uniqueTokens = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[matches[0]] = struct{}{}
	}

	for token := range uniqueTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DigitalOceanV2,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Check if the token is a refresh token or an access token
			switch {
			case strings.HasPrefix(token, "dor_v1_"):
				verified, extraData, verificationErr, newAccessToken := verifyRefreshToken(logCtx, client, token)
				s1.SetVerificationError(verificationErr)
				s1.Verified = verified
				s1.ExtraData = extraData
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key": newAccessToken,
					}
				}
			case strings.HasPrefix(token, "doo_v1_"), strings.HasPrefix(token, "dop_v1_"):
				verified, extraData, verificationErr := verifyAccessToken(logCtx, client, token)
				s1.Verified = verified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr)
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key": token,
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyRefreshToken verifies the refresh token by making a request to the DigitalOcean API.
// If the token is valid, it returns the new access token and no error.
// If the token is invalid/expired, it returns an empty string and no error.
// If an error is encountered, it returns an empty string along and the error.
func verifyRefreshToken(ctx logContext.Context, client *http.Client, token string) (bool, map[string]string, error, string) {
	// Ref: https://docs.digitalocean.com/reference/api/oauth/#token

	url := "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token=" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %w", err), ""
	}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err), ""
	}

	extraData := make(map[string]string)

	// lightweight analyze: unconditionally preserve the response body

	resBody := lwa.CopyAndCloseResponseBody(ctx, res)
	extraData[lwa.KeyResponse] = string(resBody)

	switch res.StatusCode {
	case http.StatusOK:
		var resData oauthResponse
		if err = json.Unmarshal(resBody, &resData); err != nil {
			ctx.Logger().Error(err, "failed to parse response")
			return false, extraData, err, ""
		}

		if resData.AccessToken == "" {
			return false, extraData, fmt.Errorf("access_token not found in response: %s", string(resBody)), ""
		}

		// lightweight analyze: annotate "standard" fields
		lwa.AugmentExtraData(extraData, lwa.Fields{
			ID:    &resData.Info.UUID,
			Name:  &resData.Info.Name,
			Email: &resData.Info.Email,
		})

		return true, extraData, nil, resData.AccessToken
	case http.StatusUnauthorized:
		return false, extraData, nil, ""
	default:
		return false, extraData, fmt.Errorf("unexpected status code: %d", res.StatusCode), ""
	}
}

// verifyAccessToken verifies the access token by making a request to the DigitalOcean API.
// If the token is valid, it returns true and no error.
// If the token is invalid, it returns false and no error.
// If an error is encountered, it returns false along with the error.
func verifyAccessToken(ctx logContext.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Ref: https://docs.digitalocean.com/reference/api/digitalocean/#tag/Account

	url := "https://api.digitalocean.com/v2/account"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to make request: %w", err)
	}

	extraData := make(map[string]string)

	// lightweight analyze: unconditionally preserve the response body
	resBody := lwa.CopyAndCloseResponseBody(ctx, res)
	extraData[lwa.KeyResponse] = string(resBody)

	switch res.StatusCode {
	case http.StatusOK:
		var resData accountResponse
		if err = json.Unmarshal(resBody, &resData); err != nil {
			ctx.Logger().Error(err, "failed to parse response")
			return true, extraData, nil
		}

		// lightweight analyze: annotate "standard" fields
		lwa.AugmentExtraData(extraData, lwa.Fields{
			ID:    &resData.Account.UUID,
			Name:  &resData.Account.Name,
			Email: &resData.Account.Email,
		})

		return true, extraData, nil
	case http.StatusUnauthorized:
		return false, extraData, nil
	default:
		return false, extraData, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

type accountResponse struct {
	Account struct {
		UUID  string `json:"uuid"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"account"`
}

type oauthResponse struct {
	AccessToken string `json:"access_token"`
	Info        struct {
		UUID  string `json:"uuid"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"info"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DigitalOceanV2
}

func (s Scanner) Description() string {
	return "DigitalOcean is a cloud service provider offering scalable compute and storage solutions. DigitalOcean API keys can be used to access and manage these resources."
}
