package refreshtoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
	detectors.StartOffsetProvider
} = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	refreshTokenPat = regexp.MustCompile(`\b[01]\.A[\w-]{50,}(?:\.\d)?\.Ag[\w-]{250,}(?:\.A[\w-]{200,})?`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"0.A", "1.A"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureRefreshToken
}

func (s Scanner) Description() string {
	return "Azure Entra ID refresh tokens provide long-lasting access to an account."
}

func (Scanner) MaxSecretSize() int64 { return 2048 }

func (Scanner) StartOffset() int64 { return 4096 }

// FromData will find and optionally verify Azure RefreshToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := findTokenMatches(dataStr)
	if len(tokenMatches) == 0 {
		return
	}
	clientMatches := azure_entra.FindClientIdMatches(dataStr)
	if len(clientMatches) == 0 {
		clientMatches[defaultClientId] = struct{}{}
	}
	tenantMatches := azure_entra.FindTenantIdMatches(dataStr)
	if len(tenantMatches) == 0 {
		tenantMatches[defaultTenantId] = struct{}{}
	}

	return s.processMatches(ctx, tokenMatches, clientMatches, tenantMatches, verify), err
}

func (s Scanner) processMatches(ctx context.Context, refreshTokens, clientIds, tenantIds map[string]struct{}, verify bool) (results []detectors.Result) {
	logCtx := logContext.AddLogger(ctx)
	invalidClientsForTenant := make(map[string]map[string]struct{})
	validTenants := make(map[string]struct{})

TokenLoop:
	for token := range refreshTokens {
		var (
			r        *detectors.Result
			clientId string
			tenantId string
		)

	ClientLoop:
		for cId := range clientIds {
			clientId = cId
			for tId := range tenantIds {
				tenantId = tId

				// Skip known invalid tenants.
				invalidClients := invalidClientsForTenant[tenantId]
				if invalidClients == nil {
					invalidClients = map[string]struct{}{}
					invalidClientsForTenant[tenantId] = invalidClients
				}
				if _, ok := invalidClients[clientId]; ok {
					continue
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					if _, ok := validTenants[tenantId]; !ok {
						if azure_entra.TenantExists(logCtx, client, tenantId) {
							validTenants[tenantId] = struct{}{}
						} else {
							delete(tenantIds, tenantId)
							continue
						}
					}

					isVerified, extraData, verificationErr := verifyMatch(ctx, client, token, clientId, tenantId)
					// Handle errors.
					if verificationErr != nil {
						if errors.Is(verificationErr, ErrTenantNotFound) {
							// Tenant doesn't exist. This shouldn't happen with the check above.
							delete(tenantIds, tenantId)
							continue
						} else if errors.Is(verificationErr, ErrClientNotFoundInTenant) {
							// Tenant is valid but the ClientID doesn't exist.
							invalidClients[clientId] = struct{}{}
							continue
						} else if errors.Is(verificationErr, ErrTokenExpired) {
							continue TokenLoop
						} else {
							// Received an unexpected/unhandled error type.
							r = createResult(token, clientId, tenantId, isVerified, extraData, verificationErr)
							break ClientLoop
						}
					}

					// The result is verified or there's only one associated client and tenant.
					if isVerified {
						r = createResult(token, clientId, tenantId, isVerified, extraData, verificationErr)
						break ClientLoop
					}
				}
			}
		}

		if r == nil {
			// Only include the clientId and tenantId if we're confident which one it is.
			if len(clientIds) != 1 || clientId == defaultClientId {
				clientId = ""
			}
			if len(tenantIds) != 1 || tenantId == defaultTenantId {
				tenantId = ""
			}
			r = createResult(token, clientId, tenantId, false, nil, nil)
		}

		results = append(results, *r)
	}
	return results
}

const defaultTenantId = "common"
const defaultClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c" // Microsoft Office

var (
	ErrTokenExpired           = errors.New("token expired")
	ErrTenantNotFound         = errors.New("tenant not found")
	ErrClientNotFoundInTenant = errors.New("application was not found in tenant")
)

// https://learn.microsoft.com/en-us/advertising/guides/authentication-oauth-get-tokens?view=bingads-13#refresh-accesstoken
func verifyMatch(ctx context.Context, client *http.Client, refreshToken string, clientId string, tenantId string) (bool, map[string]string, error) {
	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	tokenUrl := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantId)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenUrl, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Refresh token is valid.
	if res.StatusCode == http.StatusOK {
		var okResp successResponse
		if err := json.NewDecoder(res.Body).Decode(&okResp); err != nil {
			return false, nil, err
		}

		extraData := map[string]string{
			"Tenant": tenantId,
			"Client": clientId,
			"Scope":  okResp.Scope,
		}

		// Add claims from the access token.
		token, _ := jwt.Parse(okResp.AccessToken, nil)
		if token != nil {
			claims := token.Claims.(jwt.MapClaims)

			if app := fmt.Sprint(claims["app_displayname"]); app != "" {
				extraData["Application"] = app
			}

			// The user information can be in a few claims.
			switch {
			case claims["email"] != nil:
				extraData["User"] = fmt.Sprint(claims["email"])
			case claims["upn"] != nil:
				extraData["User"] = fmt.Sprint(claims["upn"])
			case claims["unique_name"]:
				extraData["User"] = fmt.Sprint(claims["unique_name"])
			}
		}
		return true, extraData, nil
	}

	// Credentials *probably* aren't valid.
	var errResp errorResponse
	if err := json.NewDecoder(res.Body).Decode(&errResp); err != nil {
		return false, nil, err
	}

	switch res.StatusCode {
	case http.StatusBadRequest:
		// Error codes can be looked up by removing the `AADSTS` prefix.
		// https://login.microsoftonline.com/error?code=9002313
		d := errResp.Description
		switch {
		case strings.HasPrefix(d, "AADSTS70008:"),
			strings.HasPrefix(d, "AADSTS700082:"),
			strings.HasPrefix(d, "AADSTS70043:"):
			// https://login.microsoftonline.com/error?code=70008
			// https://login.microsoftonline.com/error?code=700082
			// https://login.microsoftonline.com/error?code=70043
			return false, nil, ErrTokenExpired
		case strings.HasPrefix(d, "AADSTS700016:"):
			// https://login.microsoftonline.com/error?code=700016
			return false, nil, ErrClientNotFoundInTenant
		case strings.HasPrefix(d, "AADSTS90002:"):
			// https://login.microsoftonline.com/error?code=90002
			return false, nil, ErrTenantNotFound
		case strings.HasPrefix(d, "AADSTS9002313:"):
			// This seems to be a generic "invalid token" error code.
			// 'invalid_grant': AADSTS9002313: Invalid request. Request is malformed or invalid.
			return false, nil, nil
		default:
			return false, nil, fmt.Errorf("unexpected error '%s': %s", errResp.Error, errResp.Description)
		}
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type successResponse struct {
	Scope       string `json:"scope"`
	AccessToken string `json:"access_token"`
}

type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// region Helper methods.
func findTokenMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range refreshTokenPat.FindAllStringSubmatch(data, -1) {
		m := match[0]
		if detectors.StringShannonEntropy(m) < 4 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}
	return uniqueMatches
}

func createResult(refreshToken, clientId, tenantId string, verified bool, extraData map[string]string, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detectorspb.DetectorType_AzureRefreshToken,
		Raw:          []byte(refreshToken),
		ExtraData:    extraData,
		Verified:     verified,
	}
	r.SetVerificationError(err, refreshToken)

	if clientId != "" && tenantId != "" {
		var sb strings.Builder
		sb.WriteString(`{`)
		sb.WriteString(`"refreshToken":"` + refreshToken + `"`)
		sb.WriteString(`,"clientId":"` + clientId + `"`)
		sb.WriteString(`,"tenantId":"` + tenantId + `"`)
		sb.WriteString(`}`)
		r.RawV2 = []byte(sb.String())
	}

	return r
}

// endregion
