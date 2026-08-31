package hashicorpvaulttoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hashicorpvault"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = detectors.NewClientWithDedup(detectors.DetectorHttpClientWithNoLocalAddresses)

	// Vault tokens:
	// newer vault tokens are around 90-120 chars (exluding the prefix "hvs.") and start with hvs. (HashiCorp Vault Service token)
	// legacy tokens are around 18-40 chars (exluding the prefix "s.") and start with s.
	vaultTokenPat = regexp.MustCompile(
		`\b(hvs\.[A-Za-z0-9_-]{90,120}|s\.[A-Za-z0-9_-]{18,40})(?:$|[^A-Za-z0-9_-])`,
	)

	vaultUrlPat = regexp.MustCompile(`(https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?)(?:\/[^\s]*)?`)
)

func (s Scanner) Keywords() []string {
	// We cant use s. as a keyword because it is too broad so that's why we are using "vault".
	return []string{"hvs.", "vault"}
}

func (Scanner) CloudEndpoint() string { return "" }

func (s Scanner) Description() string {
	return "HashiCorp Vault is a secrets management service. Vault tokens (periodic, service, and admin) can be used to access and manage stored secrets and resources."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range vaultTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	var uniqueVaultUrls = make(map[string]struct{})
	for _, match := range vaultUrlPat.FindAllStringSubmatch(dataStr, -1) {
		url := strings.TrimSpace(match[1])
		uniqueVaultUrls[url] = struct{}{}
	}
	endpoints := make([]string, 0, len(uniqueVaultUrls))
	for endpoint := range uniqueVaultUrls {
		endpoints = append(endpoints, endpoint)
	}

	for token := range uniqueTokens {
		for _, endpoint := range s.Endpoints(endpoints...) {
			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_HashiCorpVaultToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + endpoint),
				Redacted:     token[:8] + "...",
				SecretParts: map[string]string{
					"key": token,
					"url": endpoint,
				},
			}

			if verify {
				verified, verificationResp, verificationErr := hashicorpvault.VerifyVaultToken(
					ctx,
					s.getClient(),
					s.Type(),
					endpoint,
					token,
				)
				result.SetVerificationError(verificationErr, token)
				result.Verified = verified
				if verificationResp != nil {
					result.ExtraData = map[string]string{
						"policies":  strings.Join(verificationResp.Data.Policies, ", "),
						"orphan":    fmt.Sprintf("%v", verificationResp.Data.Orphan),
						"renewable": fmt.Sprintf("%v", verificationResp.Data.Renewable),
						"type":      verificationResp.Data.Type,
						"entity_id": verificationResp.Data.EntityId, // can be helpful in revoking the token
					}
				}
			}

			results = append(results, result)
		}
	}

	return
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HashiCorpVaultToken
}
