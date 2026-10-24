package v2

import (
	"context"
	"errors"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
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
)

func (s Scanner) Version() int {
	return 2
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"q~"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Azure
}

func (s Scanner) Description() string {
	return serviceprincipal.Description
}

// FromData will find and optionally verify Azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientSecrets := findSecretMatches(dataStr)
	if len(clientSecrets) == 0 {
		return results, nil
	}
	clientIds := azure_entra.FindClientIdOffsets(dataStr)
	tenantIds := azure_entra.FindTenantIdOffsets(dataStr)

	client := s.client
	if client == nil {
		client = defaultClient
	}

	results = append(results, ProcessData(ctx, dataStr, clientSecrets, clientIds, tenantIds, verify, client)...)
	return results, nil
}

// ProcessData verifies each secret against the client and tenant IDs found in |data|.
// |clientIds| and |tenantIds| map each candidate to the offsets it was found at, so the
// candidates closest to a secret are tried (and reported) first.
func ProcessData(ctx context.Context, data string, clientSecrets map[string]struct{}, clientIds, tenantIds map[string][]int, verify bool, client *http.Client) (results []detectors.Result) {
	logCtx := logContext.AddLogger(ctx)
	invalidClientsForTenant := make(map[string]map[string]struct{})
	// Tenants whose lookup failed. Not retried again in this call, so one flaky tenant
	// costs one request instead of one per secret and client.
	unknownTenants := make(map[string]struct{})

	for clientSecret := range clientSecrets {
		var (
			r *detectors.Result
			// The first client/tenant pair that recognised the app but rejected the secret.
			knownClientId, knownTenantId string
		)

		// Candidates nearest to the secret are the most likely to belong to it.
		secretPos := strings.Index(data, clientSecret)
		clientOrder := azure_entra.NearestFirst(clientIds, secretPos)
		tenantOrder := azure_entra.NearestFirst(tenantIds, secretPos)

	ClientLoop:
		for _, clientId := range clientOrder {
			// Skip candidates removed earlier (e.g., a tenant that was also read as a client).
			if _, ok := clientIds[clientId]; !ok {
				continue
			}
			for _, tenantId := range tenantOrder {
				if _, ok := tenantIds[tenantId]; !ok {
					continue
				}

				if _, unknown := unknownTenants[tenantId]; unknown {
					continue
				}

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
					exists, err := azure_entra.TenantExists(logCtx, client, tenantId)
					if err != nil {
						// Unknown, not "missing". Skip it for now but keep it as a candidate.
						// If no pair is recognised, the fallback still picks the nearest tenant.
						unknownTenants[tenantId] = struct{}{}
						continue
					}
					if !exists {
						// Tenant doesn't exist
						delete(tenantIds, tenantId)
						continue
					}
					// Tenant exists, ensure this isn't attempted as a clientId.
					delete(clientIds, tenantId)

					isVerified, extraData, verificationErr := serviceprincipal.VerifyCredentials(ctx, client, tenantId, clientId, clientSecret)
					// Handle errors.
					if verificationErr != nil {
						switch {
						case errors.Is(verificationErr, serviceprincipal.ErrConditionalAccessPolicy):
							// Do nothing.
						case errors.Is(verificationErr, serviceprincipal.ErrSecretInvalid):
							// The app exists in this tenant, only the secret is wrong (e.g.,
							// rotated). Remember the pair so the fallback matches the live result.
							if knownClientId == "" {
								knownClientId, knownTenantId = clientId, tenantId
							}
							continue ClientLoop
						case errors.Is(verificationErr, serviceprincipal.ErrSecretExpired):
							r = createResult(tenantId, clientId, clientSecret, false, nil, nil)
							break ClientLoop
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
				}
			}
		}

		if r == nil {
			// Nothing verified. Use the pair Azure recognised, if any. Otherwise report
			// the nearest tenant, then the nearest client that isn't ruled out for it.
			// This keeps the result the same whether the secret is live or rotated.
			clientId, tenantId := knownClientId, knownTenantId
			if clientId == "" {
				clientId, tenantId = nearestPair(clientIds, tenantIds, invalidClientsForTenant, secretPos)
			}
			r = createResult(tenantId, clientId, clientSecret, false, nil, nil)
		}

		results = append(results, *r)
	}
	return results
}

// nearestPair picks the tenant nearest to |pos|, then the nearest client that isn't
// ruled out for that tenant and isn't the tenant itself.
func nearestPair(clientIds, tenantIds map[string][]int, invalidClientsForTenant map[string]map[string]struct{}, pos int) (clientId, tenantId string) {
	if remaining := azure_entra.NearestFirst(tenantIds, pos); len(remaining) > 0 {
		tenantId = remaining[0]
	}
	for _, candidate := range azure_entra.NearestFirst(clientIds, pos) {
		if _, ruledOut := invalidClientsForTenant[tenantId][candidate]; ruledOut || candidate == tenantId {
			continue
		}
		return candidate, tenantId
	}
	return "", tenantId
}

func createResult(tenantId string, clientId string, clientSecret string, verified bool, extraData map[string]string, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detector_typepb.DetectorType_Azure,
		Raw:          []byte(clientSecret),
		SecretParts:  map[string]string{"key": clientSecret},
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

func findSecretMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range SecretPat.FindAllStringSubmatch(data, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	return uniqueMatches
}
