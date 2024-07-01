package v2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.Versioner
} = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	SecretPat = regexp.MustCompile(`(?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)`)
	//clientSecretPat = regexp.MustCompile(`(?:[^a-zA-Z0-9_~.-]|\A)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|\z)|(?:secret|password| -p[ =]).{0,80}[^A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\\\]^_{|}~]([A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\\\]^_{|}~]{31,34})[^A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\\\]^_{|}~]`)
)

func (s Scanner) Version() int {
	return 2
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"q~"}
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientSecrets := findSecretMatches(dataStr)
	if len(clientSecrets) == 0 {
		return results, nil
	}
	clientIds := azure_entra.FindClientIdMatches(dataStr)
	tenantIds := azure_entra.FindTenantIdMatches(dataStr)

	client := s.client
	if client == nil {
		client = defaultClient
	}

	processedResults := ProcessData(ctx, clientSecrets, clientIds, tenantIds, verify, client)
	for _, result := range processedResults {
		results = append(results, result)
	}
	return results, nil
}

func ProcessData(ctx context.Context, clientSecrets, clientIds, tenantIds map[string]struct{}, verify bool, client *http.Client) (results []detectors.Result) {
	invalidClientsForTenant := make(map[string]map[string]struct{})

SecretLoop:
	for clientSecret := range clientSecrets {
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
					if !isValidTenant(ctx, client, tenantId) {
						// Tenant doesn't exist
						delete(tenantIds, tenantId)
						continue
					}

					isVerified, extraData, verificationErr := serviceprincipal.VerifyCredentials(ctx, client, tenantId, clientId, clientSecret)
					// Handle errors.
					if verificationErr != nil {
						switch {
						case errors.Is(verificationErr, serviceprincipal.ErrSecretInvalid):
							continue ClientLoop
						case errors.Is(verificationErr, serviceprincipal.ErrSecretExpired):
							continue SecretLoop
						case errors.Is(verificationErr, serviceprincipal.ErrTenantNotFound):
							// Tenant doesn't exist. This shouldn't happen with the check above.
							delete(tenantIds, tenantId)
							continue
						case errors.Is(verificationErr, serviceprincipal.ErrClientNotFoundInTenant):
							// Tenant is valid but the ClientID doesn't exist.
							invalidClients[clientId] = struct{}{}
							continue
						}
					}

					// The result is verified or there's only one associated client and tenant.
					if isVerified || (len(clientIds) == 1 && len(tenantIds) == 1) {
						r = createResult(tenantId, clientId, clientSecret, isVerified, extraData, verificationErr)
						break ClientLoop
					}

					// The result may be valid for another client/tenant.
					//
					//
					//// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-access-token-with-a-client_secret
					//cred := auth.NewClientCredentialsConfig(clientId, clientSecret, tenantId)
					//token, err := cred.ServicePrincipalToken()
					//if err != nil {
					//	// This can only fail if a value is empty, which shouldn't be possible.
					//	continue
					//}
					//
					//err = token.Refresh()
					//if err != nil {
					//	var refreshError adal.TokenRefreshError
					//	if ok := errors.As(err, &refreshError); ok {
					//		resp := refreshError.Response()
					//		defer func() {
					//			// Ensure we drain the response body so this connection can be reused.
					//			_, _ = io.Copy(io.Discard, resp.Body)
					//			_ = resp.Body.Close()
					//		}()
					//
					//		status := resp.StatusCode
					//		errStr := refreshError.Error()
					//		if status == 400 {
					//			if strings.Contains(errStr, `"error_description":"AADSTS90002:`) {
					//				// Tenant doesn't exist
					//				delete(tenantIds, tenantId)
					//				continue
					//			} else if strings.Contains(errStr, `"error_description":"AADSTS700016:`) {
					//				// Tenant is valid but the ClientID doesn't exist.
					//				invalidTenantsForClientId[clientId] = append(invalidTenantsForClientId[clientId], tenantId)
					//				continue
					//			} else {
					//				// Unexpected error.
					//				r.SetVerificationError(refreshError, clientSecret)
					//				break
					//			}
					//		} else if status == 401 {
					//			// Tenant exists and the clientID is valid, but something is wrong.
					//			if strings.Contains(errStr, `"error_description":"AADSTS7000215:`) {
					//				// Secret is not valid.
					//				setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
					//				continue IdLoop
					//			} else if strings.Contains(errStr, `"error_description":"AADSTS7000222:`) {
					//				// The secret is expired.
					//				setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
					//				continue SecretLoop
					//			} else {
					//				// TODO: Investigate if it's possible to get a 401 with a valid id/secret.
					//				r.SetVerificationError(refreshError, clientSecret)
					//				break
					//			}
					//		} else {
					//			// Unexpected status code.
					//			r.SetVerificationError(refreshError, clientSecret)
					//			break
					//		}
					//	} else {
					//		// Unexpected error.
					//		r.SetVerificationError(err, clientSecret)
					//		break
					//	}
					//} else {
					//	r.Verified = true
					//	r.ExtraData = map[string]string{
					//		"token": token.OAuthToken(),
					//	}
					//	setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
					//	break
					//}
				}
			}
		}

		if r == nil {
			// Only include the clientId and tenantId if we're confident which one it is.
			if len(clientIds) != 1 {
				clientId = ""
			}
			if len(tenantIds) != 1 {
				tenantId = ""
			}
			r = createResult(tenantId, clientId, clientSecret, false, nil, nil)
		}

		results = append(results, *r)
	}
	return results
}

func createResult(tenantId string, clientId string, clientSecret string, verified bool, extraData map[string]string, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detectorspb.DetectorType_Azure,
		Raw:          []byte(clientSecret),
		ExtraData:    extraData,
		Verified:     verified,
		Redacted:     clientSecret[:5] + "...",
	}
	r.SetVerificationError(err, clientSecret)

	// Tenant ID is required for verification, but it may not always be present.
	// e.g., ACR or Azure SQL use client id+secret without tenant.
	if clientId != "" && tenantId != "" {
		var sb strings.Builder
		sb.WriteString(`{`)
		sb.WriteString(`"clientSecret":"` + clientSecret + `"`)
		sb.WriteString(`,"clientId":"` + clientId + `"`)
		sb.WriteString(`,"tenantId":"` + tenantId + `"`)
		sb.WriteString(`}`)
		r.RawV2 = []byte(sb.String())
	}

	return r
}

func isValidTenant(ctx context.Context, client *http.Client, tenant string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", tenant), nil)
	if err != nil {
		return false
	}
	res, err := client.Do(req)
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode == 200 {
		return true
	} else if res.StatusCode == 400 {
		fmt.Printf("Invalid tenant: %s\n", tenant)
		return false
	} else {
		fmt.Printf("[azure] Unexpected status code: %d for %s\n", res.StatusCode, tenant)
		return false
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Azure
}

// region Helper methods.
func findSecretMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range SecretPat.FindAllStringSubmatch(data, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	return uniqueMatches
}

//endregion
