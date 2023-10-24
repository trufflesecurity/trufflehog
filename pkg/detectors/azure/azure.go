package azure

import (
	"context"
	"github.com/go-errors/errors"
	regexp "github.com/wasilibs/go-re2"
	"slices"
	"strings"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure/auth"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func uuidPattern(identifiers ...string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString(`(?i)(?:`)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(`).{0,80}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
	return regexp.MustCompile(sb.String())
}

// https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli-service-principal
var (
	// TODO: Support `.onmicrosoft.com` tenant IDs.
	tenantIDPat = uuidPattern("t[ae]n[ae]nt(?:[._-]?id)?", `login\.microsoftonline\.com/`)
	// TODO: support URL-based client IDs
	clientIDPat = uuidPattern("(?:app(?:lication)?|client)[._-]?id", "username", "-u")
	// TODO: support old patterns
	// TODO: Azure storage access keys and investigate other types of creds.
	clientSecretPat = regexp.MustCompile(`([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"Q~"}
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Create a deduplicated set of results.
	// This helps performance in large chunks with lots of duplicates.
	clientSecrets := make(map[string]bool)
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		clientSecrets[match[1]] = true
	}
	if len(clientSecrets) == 0 {
		return results, nil
	}
	clientIds := make(map[string]bool)
	for _, match := range clientIDPat.FindAllStringSubmatch(dataStr, -1) {
		if detectors.IsKnownFalsePositiveUuid(match[1]) {
			continue
		}
		clientIds[match[1]] = true
	}
	// A client secret without a client id is useless.
	//if len(clientIds) == 0 {
	//	return results, nil
	//}
	tenantIds := make(map[string]bool)
	for _, match := range tenantIDPat.FindAllStringSubmatch(dataStr, -1) {
		if detectors.IsKnownFalsePositiveUuid(match[1]) {
			continue
		}
		tenantIds[match[1]] = true
	}

	processedResults := processData(clientSecrets, clientIds, tenantIds, verify)
	for _, result := range processedResults {
		results = append(results, result)
	}
	return results, nil
}

func processData(clientSecrets, clientIds, tenantIds map[string]bool, verify bool) (results []detectors.Result) {
	invalidTenantsForClientId := make(map[string][]string)

SecretLoop:
	for clientSecret, _ := range clientSecrets {
		clientSecret := clientSecret
		secretReported := false

		var s detectors.Result
		var clientId string
		var tenantId string

	IdLoop:
		for cId, _ := range clientIds {
			clientId = cId

			for tId, _ := range tenantIds {
				tenantId = tId

				// Skip known invalid tenants.
				if slices.Contains(invalidTenantsForClientId[clientId], tenantId) {
					continue
				}

				if verify {
					s = createResult(clientSecret, clientId, tenantId)

					// https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-access-token-with-a-client_secret
					cred := auth.NewClientCredentialsConfig(clientId, clientSecret, tenantId)
					token, err := cred.ServicePrincipalToken()
					if err != nil {
						// This can only fail if a value is empty, which shouldn't be possible.
						continue
					}

					err = token.Refresh()
					if err != nil {
						var refreshError adal.TokenRefreshError
						if ok := errors.As(err, &refreshError); ok {
							resp := refreshError.Response()
							defer resp.Body.Close()

							status := resp.StatusCode
							errStr := refreshError.Error()
							if status == 400 {
								if strings.Contains(errStr, `"error_description":"AADSTS90002:`) {
									// Tenant doesn't exist
									delete(tenantIds, tenantId)
									continue
								} else if strings.Contains(errStr, `"error_description":"AADSTS700016:`) {
									// Tenant is valid but the ClientID doesn't exist.
									invalidTenantsForClientId[clientId] = append(invalidTenantsForClientId[clientId], tenantId)
									continue
								} else {
									// Unexpected error.
									s.SetVerificationError(refreshError, clientSecret)
									break
								}
							} else if status == 401 {
								// Tenant exists and the clientID is valid, but something is wrong.
								if strings.Contains(errStr, `"error_description":"AADSTS7000215:`) {
									// Secret is not valid.
									setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
									continue IdLoop
								} else if strings.Contains(errStr, `"error_description":"AADSTS7000222:`) {
									// The secret is expired.
									setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
									continue SecretLoop
								} else {
									// TODO: Investigate if it's possible to get a 401 with a valid id/secret.
									s.SetVerificationError(refreshError, clientSecret)
									break
								}
							} else {
								// Unexpected status code.
								s.SetVerificationError(refreshError, clientSecret)
								break
							}
						} else {
							// Unexpected error.
							s.SetVerificationError(err, clientSecret)
							break
						}
					} else {
						s.Verified = true
						setValidTenantIdForClientId(clientId, tenantId, tenantIds, invalidTenantsForClientId)
						break
					}
				}
			}

			if s.Verified {
				results = append(results, s)
				continue SecretLoop
			} else if s.VerificationError != nil {
				secretReported = true
				results = append(results, s)
			}
		}

		// The secret pattern is unique enough that we should still report it
		// if it hasn't already been added.
		if !secretReported {
			// Only include the clientId and tenantId if we're confident which one it is.
			if len(clientIds) != 1 {
				clientId = ""
			}
			if len(tenantIds) != 1 {
				tenantId = ""
			}
			s = createResult(clientSecret, clientId, tenantId)
			results = append(results, s)
		}
	}
	return results
}

func setValidTenantIdForClientId(clientId, validTenantId string, tenantIds map[string]bool, invalidTenantsForClientId map[string][]string) {
	for id := range tenantIds {
		if id != validTenantId {
			invalidTenantsForClientId[clientId] = append(invalidTenantsForClientId[clientId], id)
		}
	}
}

func createResult(clientSecret, clientId, tenantId string) detectors.Result {
	s := detectors.Result{
		DetectorType: detectorspb.DetectorType_Azure,
		Raw:          []byte(clientSecret),
		// Set the RotationGuideURL in the ExtraData
		ExtraData: map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/azure/",
		},
	}

	if clientId != "" {
		s.Redacted = clientId

		// Tenant ID is required for verification, but it may not always be present.
		// e.g., ACR or Azure SQL use client id+secret without tenant.
		if tenantId != "" {
			s.RawV2 = []byte(clientId + ":" + clientSecret + " (" + tenantId + ")")
		} else {
			s.RawV2 = []byte(clientId + ":" + clientSecret)
		}
	}

	return s
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Azure
}
