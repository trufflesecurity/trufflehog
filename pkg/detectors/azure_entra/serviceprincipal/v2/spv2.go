package v2

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azure_entra/serviceprincipal"
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
)

func (s Scanner) Version() int {
	return 2
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"q~"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Azure
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
	clientIds := azure_entra.FindClientIdMatches(dataStr)
	tenantIds := azure_entra.FindTenantIdMatches(dataStr)

	client := s.client
	if client == nil {
		client = defaultClient
	}

	results = append(results, ProcessData(ctx, clientSecrets, clientIds, tenantIds, verify, client)...)
	return results, nil
}

func ProcessData(ctx context.Context, clientSecrets, clientIds, tenantIds map[string]struct{}, verify bool, client *http.Client) (results []detectors.Result) {
	logCtx := logContext.AddLogger(ctx)
	invalidClientsForTenant := make(map[string]map[string]struct{})

	// Clone maps so verification-driven deletions don't mutate the caller's
	// data or produce non-deterministic results across scanner runs.
	activeClients := maps.Clone(clientIds)
	activeTenants := maps.Clone(tenantIds)

SecretLoop:
	for _, clientSecret := range slices.Sorted(maps.Keys(clientSecrets)) {
		var (
			r        *detectors.Result
			clientId string
			tenantId string
		)

	ClientLoop:
		for _, cId := range slices.Sorted(maps.Keys(activeClients)) {
			if _, ok := activeClients[cId]; !ok {
				continue
			}
			clientId = cId
			for _, tId := range slices.Sorted(maps.Keys(activeTenants)) {
				if _, ok := activeTenants[tId]; !ok {
					continue
				}
				tenantId = tId

				invalidClients := invalidClientsForTenant[tenantId]
				if invalidClients == nil {
					invalidClients = map[string]struct{}{}
					invalidClientsForTenant[tenantId] = invalidClients
				}
				if _, ok := invalidClients[clientId]; ok {
					continue
				}

				if verify {
					if !azure_entra.TenantExists(logCtx, client, tenantId) {
						delete(activeTenants, tenantId)
						continue
					}
					delete(activeClients, tenantId)

					isVerified, extraData, verificationErr := serviceprincipal.VerifyCredentials(ctx, client, tenantId, clientId, clientSecret)
					if verificationErr != nil {
						switch {
						case errors.Is(verificationErr, serviceprincipal.ErrConditionalAccessPolicy):
							// Do nothing.
						case errors.Is(verificationErr, serviceprincipal.ErrSecretInvalid):
							continue ClientLoop
						case errors.Is(verificationErr, serviceprincipal.ErrSecretExpired):
							continue SecretLoop
						case errors.Is(verificationErr, serviceprincipal.ErrTenantNotFound):
							delete(activeTenants, tenantId)
							continue
						case errors.Is(verificationErr, serviceprincipal.ErrClientNotFoundInTenant):
							invalidClients[clientId] = struct{}{}
							continue
						}
					}

					if isVerified || (len(activeClients) == 1 && len(activeTenants) == 1) {
						r = createResult(tenantId, clientId, clientSecret, isVerified, extraData, verificationErr)
						break ClientLoop
					}
				}
			}
		}

		if r == nil {
			if len(activeClients) != 1 {
				clientId = ""
			}
			if len(activeTenants) != 1 {
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

func findSecretMatches(data string) map[string]struct{} {
	uniqueMatches := make(map[string]struct{})
	for _, match := range SecretPat.FindAllStringSubmatch(data, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	return uniqueMatches
}
